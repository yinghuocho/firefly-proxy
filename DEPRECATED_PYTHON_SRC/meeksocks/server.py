import logging
from logging.handlers import WatchedFileHandler
import sys
import os
import time
import getopt
from sys import platform as _platform
if _platform == "linux" or _platform == "linux2":
    os.environ['GEVENT_RESOLVER'] = "ares"

import gevent
from gevent import select
from gevent import socket
from gevent.pywsgi import WSGIServer
from gevent.queue import Queue, Empty
from gevent.event import Event

from gsocks.server import SocksServer
from gsocks.relay import SocksRelayFactory, RelaySessionError
from gsocks.utils import SharedTimer, read_init_reply, bind_local_udp, sock_addr_info, \
read_reply
from gsocks.msg import InitRequest, Request, UDP_ASSOCIATE, CONNECT, BIND
from constants import MAX_PAYLOAD_LENGTH, HEADER_SESSION_ID, HEADER_UDP_PKTS, \
HEADER_MODE, HEADER_MSGTYPE, MSGTYPE_DATA, MODE_STREAM, HEADER_ERROR, \
CLIENT_MAX_POLL_INTERVAL, MSGTYPE_TERMINATE, SERVER_TURNAROUND_TIMEOUT, \
SERVER_TURNAROUND_MAX

log = logging.getLogger(__name__)

SESSION_WAIT_INIT       = 0
SESSION_WAIT_REQUEST    = 1
SESSION_TCP             = 2
SESSION_UDP             = 3

class globalvars(object):
    meek_sessions   = {}
    socksip         = "0.0.0.0"
    socksport       = 1080
    sockstimeout    = 60
    
class options(object):
    daemonize = False
    logginglevel = logging.INFO
    pidfile   = "meeksocks_server.pid"
    logfile   = "meeksocks_server.log"

class MeekSession(object):
    def __init__(self, sessionid, socksip, socksport, timeout, sessionmap):
        self.sessionid = sessionid
        self.socksip = socksip
        self.socksport = socksport
        self.timeout = timeout
        self.sessionmap = sessionmap
        self.sessionmap[self.sessionid] = self
        self.udpsock = None
        self.udp_associate = None
        self.socksconn = None
        self.allsocks = []
        self.status = SESSION_WAIT_INIT
        
        self.initialized = False
        self.in_queue = Queue()
        self.in_notifier = Event()
        self.in_notifier.clear()
        self.out_queue = Queue()
        self.timer = SharedTimer(self.timeout)
        self.finish = Event()
        self.finish.clear()
        
        self.threads = []
    
    def meeks_clean_thread(self):
        while not self.finish.is_set():
            gevent.sleep(SERVER_TURNAROUND_MAX)
        [t.join() for t in self.threads]
        self.clean()
            
    def write_to_socks(self, data):
        if self.udpsock:
            self.udpsock.sendto(data, self.udp_associate)
        else:
            self.socksconn.sendall(data)
            
    def meeks_write_to_socks_thread(self):
        while not self.finish.is_set():
            try:
                hasdata = self.in_notifier.wait(timeout=CLIENT_MAX_POLL_INTERVAL)
                self.in_notifier.clear()
                if not hasdata:
                    self.timer.count(CLIENT_MAX_POLL_INTERVAL)
                if self.timer.timeout():
                    break
                self.timer.reset()
                while not self.in_queue.empty():
                    data = self.in_queue.get()
                    log.debug("%s: RELAY-UP %d bytes" % (self.sessionid, len(data)))
                    self.write_to_socks(data)
            except Exception as ex:
                log.error("[Exception][meeks_write_to_socks_thread] %s: %s" % (self.sessionid, str(ex)))
                break
        self.finish.set()
        
    def meeks_read_from_socks_thread(self):
        while not self.finish.is_set():
            try:
                readable, _, _ = select.select(self.allsocks, [], [], CLIENT_MAX_POLL_INTERVAL)
                if not readable:
                    self.timer.count(CLIENT_MAX_POLL_INTERVAL)
                    if self.timer.timeout():
                        break
                else:
                    self.timer.reset()
                    if self.socksconn in readable:
                        if self.udpsock:
                            raise RelaySessionError("unexcepted read-event from tcp socket in UDP session")
                        data = self.socksconn.recv(MAX_PAYLOAD_LENGTH)
                        if not data:
                            raise RelaySessionError("peer closed")
                        self.out_queue.put(data)
                        continue
                    if self.udpsock and self.udpsock in readable:
                        data, _ = self.udpsock.recvfrom(MAX_PAYLOAD_LENGTH)
                        if data:
                            self.out_queue.put(data)
            except Exception as ex:
                log.error("[Exception][meeks_read_from_socks_thread] %s:%s" % (self.sessionid, str(ex)))
                break
        self.finish.set()
        
    def initialize(self):
        self.socksconn = socket.create_connection((self.socksip, self.socksport), self.timeout)
        self.allsocks = [self.socksconn]
        self.socksconn.sendall(InitRequest().pack())
        read_init_reply(self.socksconn)
        self.status = SESSION_WAIT_REQUEST
        self.initialized = True
    
    def cmd_connect(self, req):
        self.socksconn.sendall(req.pack())
        reply = read_reply(self.socksconn)
        resp = reply.pack()
        headers = [
            (HEADER_SESSION_ID, self.sessionid),
            (HEADER_MSGTYPE, MSGTYPE_DATA)
        ]
        
        self.threads.append(gevent.spawn(self.meeks_write_to_socks_thread))
        self.threads.append(gevent.spawn(self.meeks_read_from_socks_thread))
        # clean_thread will join the other two threads, then clean resources
        gevent.spawn(self.meeks_clean_thread)
        self.status = SESSION_TCP
        return resp, headers
        
    def cmd_udp_associate(self, req):
        self.udpsock = bind_local_udp(self.socksconn)
        self.allsocks.append(self.udpsock)
        addrtype, ip, port = sock_addr_info(self.udpsock)
        self.socksconn.sendall(Request(cmd=UDP_ASSOCIATE,
            addrtype=addrtype, dstaddr=ip, dstport=port).pack())
        reply = read_reply(self.socksconn)
        resp = reply.pack()
        headers = [
            (HEADER_SESSION_ID, self.sessionid),
            (HEADER_MSGTYPE, MSGTYPE_DATA)
        ]
        
        self.udp_associate = (reply.bndaddr, reply.bndport)
        self.threads.append(gevent.spawn(self.meeks_write_to_socks_thread))
        self.threads.append(gevent.spawn(self.meeks_read_from_socks_thread))
        # clean_thread will join the other two threads, then clean resources
        gevent.spawn(self.meeks_clean_thread)
        self.status = SESSION_UDP
        return resp, headers
    
    def cmd_bind(self, req):
        resp = ""
        headers = [
            (HEADER_SESSION_ID, self.sessionid),
            (HEADER_ERROR, "Not Supported")
        ]
        return resp, headers
    
    def sync_socks_request(self, data, env):
        req = Request()
        req.unpack(data)
        return {
            CONNECT: self.cmd_connect,
            BIND: self.cmd_bind,
            UDP_ASSOCIATE : self.cmd_udp_associate
        }[req.cmd](req)
        
    def _fetch_resp(self):
        data = []
        totalsize = 0
        while True:
            while not self.out_queue.empty() and totalsize < MAX_PAYLOAD_LENGTH:
                pkt = self.out_queue.get()
                data.append(pkt)
                totalsize += len(pkt)
            if data:
                return data, totalsize
            else:
                try:
                    self.out_queue.peek(block=True, timeout=SERVER_TURNAROUND_TIMEOUT)
                except Empty:
                    break
        return data, totalsize
        
    def fetch_resp(self):
        data, _ = self._fetch_resp()
        resp = "".join(data)
        headers = [
            (HEADER_SESSION_ID, self.sessionid),
            (HEADER_MSGTYPE, MSGTYPE_DATA),
        ]
        if self.status == SESSION_UDP and data:
            headers.append((HEADER_UDP_PKTS, ",".join([str(len(d)) for d in data])))
        return resp, headers
    
    def process_tcp(self, data, env):
        if data:
            self.in_queue.put(data)
            self.in_notifier.set()
        return self.fetch_resp()
        
    def process_udp(self, data, env):
        if data:
            lengths = env[header_to_env(HEADER_UDP_PKTS)].split(",")
            pos = 0
            for length in lengths:
                nxt = pos + int(length)
                self.in_queue.put(data[pos:nxt])
                pos = nxt
            self.in_notifier.set()
        return self.fetch_resp()
        
    def process(self, data, env):
        if not self.initialized:
            self.initialize()
    
        return {
            SESSION_WAIT_REQUEST: self.sync_socks_request,
            SESSION_TCP: self.process_tcp,
            SESSION_UDP: self.process_udp,
        }[self.status](data, env)    
    
    def alive(self):
        return not self.finish.is_set()
    
    def clean(self):
        self.finish.set()
        for sock in self.allsocks:
            sock.close()
            
        self.in_queue.queue.clear()
        self.out_queue.queue.clear()
        if self.sessionid in self.sessionmap:
            del self.sessionmap[self.sessionid]
            log.info("%s: quit, %d sessions left" % (self.sessionid, len(self.sessionmap.keys())))
    
def header_to_env(header):
    return ("http-" + header).replace("-", "_").upper()
    
def meek_tcp_stream(status, response_headers, session, data, start_response):
    session.in_queue.put(data)
    session.in_notifier.set()
    start = time.time()
    end = start
    response_headers.append((HEADER_SESSION_ID, session.sessionid))
    response_headers.append((HEADER_MSGTYPE, MSGTYPE_DATA))
    start_response(status, response_headers)
    while (end - start)<SERVER_TURNAROUND_MAX and session.alive():
        while not session.out_queue.empty():
            pkt = session.out_queue.get()
            log.debug("%s: RELAY-DOWN streaming %d bytes" % (session.sessionid, len(pkt)))
            yield pkt
        try:
            session.out_queue.peek(block=True, timeout=SERVER_TURNAROUND_TIMEOUT)
        except Empty:
            pass
        end = time.time()
       
def meek_server_application(env, start_response):
    status = '200 OK'
    if env['REQUEST_METHOD'] == "GET":
        response_headers = [
            ('Content-Type', 'text/html; charset=UTF-8'),
        ] 
        start_response(status, response_headers)
        return "Hello, world!"
    
    response_headers = [
        ('Content-Type', 'application/octet-stream'),
    ]
    
    sessionid = env.get(header_to_env(HEADER_SESSION_ID), "")
    msgtype   = env.get(header_to_env(HEADER_MSGTYPE), "")
    if not sessionid:
        log.error("request without sesessionid")
        response_headers.append((HEADER_ERROR, "SessionID Missed"))
        start_response(status, response_headers)
        return ""
    
    session = globalvars.meek_sessions.get(sessionid, None)
    if msgtype == MSGTYPE_TERMINATE:
        if session:
            log.info("%s: terminated by client" % sessionid)
            session.clean()
        response_headers.append((HEADER_SESSION_ID, sessionid))
        start_response(status, response_headers)
        return ""
    
    if not session:
        log.info("%s: new session created" % sessionid)
        session = MeekSession(sessionid, globalvars.socksip,    
                globalvars.socksport, globalvars.sockstimeout, globalvars.meek_sessions)
    
    data = env['wsgi.input'].read()
    log.debug("%s: request with %d data" % (sessionid, len(data)))
    if env.get(header_to_env(HEADER_MODE), "") == MODE_STREAM and session.status == SESSION_TCP:
        return meek_tcp_stream(status, response_headers, session, data, start_response)
    else:
        try:
            response, headers = session.process(data, env.copy())
            log.debug("%s: RELAY-DOWN %d bytes" % (session.sessionid, len(response)))
            response_headers += headers
            start_response(status, response_headers)
            return [response]
        except Exception as ex:
            log.error("[Exception][meek] %s: %s" % (session.sessionid, str(ex)))
            session.clean()
            response_headers.append((HEADER_SESSION_ID, session.sessionid))
            response_headers.append((HEADER_ERROR, "Internal Error"))    
            start_response(status, response_headers)
            return []
       
def usage(f = sys.stdout):
    print >> f, """
Usage: python meeksocks-server.py http_ip http_port socks_ip socks_port [OPTIONS]

Options:
  -h, --help        display this information.
  -d, --debug       more verbose logging
  -p, --pidfile     file to write pid, implies daemonization.
  -l, --logfile     file to write log, also implies daemonization.
"""

def main():
    if len(sys.argv) < 5:
        usage(f = sys.stderr)
        sys.exit(-1)
        
    http_ip = sys.argv[1]
    http_port = int(sys.argv[2])
    socksip = sys.argv[3]
    socksport = int(sys.argv[4])
    
    opts, _ = getopt.gnu_getopt(sys.argv[5:], "hdp:l:",
                            ["help", "debug", "pidfile=", "logfile="])
    for o, a in opts:
        if o == "-h" or o == "--help":
            usage()
            sys.exit()
        if o == "-d" or o == "--debug":
            options.logginglevel = logging.DEBUG
        elif o == "-p" or o == "--pidfile":
            options.daemonize = True
            options.pidfile = a
        elif o == "-l" or o == "--logfile":
            options.daemonize = True
            options.logfile = a
            
    if options.daemonize:
        pid = os.fork()
        if pid != 0:
            # write pidfile by father
            f = open(options.pidfile, "w")
            print >> f, pid
            f.close()
            sys.exit(0)
    
    if options.daemonize:
        logger = logging.getLogger()
        logger.setLevel(options.logginglevel)
        ch = WatchedFileHandler(options.logfile)
        ch.setFormatter(logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s] - %(message)s'))
        logger.addHandler(ch)
    else:
        logging.basicConfig(
            format='[%(asctime)s][%(name)s][%(levelname)s] - %(message)s',
            datefmt='%Y-%d-%m %H:%M:%S',
            level=options.logginglevel,    
        )
    
    socks = SocksServer(socksip, socksport, SocksRelayFactory(), timeout=30, maxclient=500)
    socks.start()

    globalvars.socksip = socksip
    globalvars.socksport = socksport
    globalvars.sockstimeout = 60
    WSGIServer((http_ip, http_port), meek_server_application, log=None).serve_forever()
        
if __name__ == '__main__':
    main()
        
        