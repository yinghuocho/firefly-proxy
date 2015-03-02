# a relay forward local socks to a remote socks through meek (i.e., HTTP transport).
import logging
import uuid
import random
import ssl
from collections import defaultdict

import gevent
from gevent import select
from gevent import socket
from gevent.queue import Queue, LifoQueue
from gevent.event import Event

from geventhttpclient import HTTPClient, URL

from relay import RelayFactory, RelaySession, RelaySessionError
from msg import Reply, GENERAL_SOCKS_SERVER_FAILURE
from meek import SESSION_ID_LENGTH, MAX_PAYLOAD_LENGTH, HEADER_SESSION_ID, \
HEADER_UDP_PKTS, HEADER_MODE, HEADER_MSGTYPE, MSGTYPE_DATA, MODE_STREAM, \
HEADER_ERROR, CLIENT_MAX_TRIES, CLIENT_RETRY_DELAY, CLIENT_INITIAL_POLL_INTERVAL, \
CLIENT_POLL_INTERVAL_MULTIPLIER, CLIENT_MAX_POLL_INTERVAL, MSGTYPE_TERMINATE, \
CLIENT_MAX_FAILURE
from utils import SharedTimer, bind_local_udp, request_fail, request_success, \
sock_addr_info

log = logging.getLogger(__name__)

def session_id():
    return str(uuid.uuid4())[:SESSION_ID_LENGTH]
        
def get_meek_meta(headers, key, default=""):
    # requests lib gives lower-string headers
    return dict(headers).get(key.lower(), default)    

class Relay:
    def __init__(self, fronturl="", hostname="", properties="", failure=0):
        self.fronturl = fronturl
        self.hostname = hostname
        self.properties = properties
        self.failure = failure 
        
class HTTPClientPool:
    def __init__(self):
        self.pool = defaultdict(LifoQueue)
        
    def get(self, relay, ca_certs, timeout):
        try:
            return self.pool[relay.fronturl].get(block=False)
        except gevent.queue.Empty:
            insecure = "verify" not in relay.properties
            if ca_certs:
                ssl_options = {'ca_certs': ca_certs, 'ssl_version': ssl.PROTOCOL_TLSv1}
            else:
                ssl_options = {}
            conn = HTTPClient.from_url(
                URL(relay.fronturl), 
                insecure=insecure,
                block_size=MAX_PAYLOAD_LENGTH,
                connection_timeout=timeout,
                network_timeout=timeout,
                concurrency=1,
                ssl_options=ssl_options
            )
            return conn
        
    def release(self, relay, conn):
        self.pool[relay.fronturl].put(conn)
          
class MeekSession(RelaySession):  
    conn_pool = HTTPClientPool()
    
    def __init__(self, socksconn, meek, timeout):
        super(MeekSession, self).__init__(socksconn)
        self.sessionid = session_id()
        self.meek = meek
        self.meektimeout = timeout
        self.relay = self.meek.select_relay()
        self.ca_certs = self.meek.ca_certs
    
        self.httpclient = self.conn_pool.get(self.relay, self.ca_certs, self.meektimeout)
        
        self.udpsock = None
        self.allsocks = [self.socksconn]
        
        self.l2m_queue = Queue()
        self.m2l_queue = Queue()
        self.m_notifier = Event()
        self.l_notifier = Event()
        self.finish = Event()
        self.m_notifier.clear()
        self.l_notifier.clear()
        self.finish.clear()
        self.timer = SharedTimer(self.meektimeout)
        
    def _stream_response(self, response):
        try:
            chunk = response.read(MAX_PAYLOAD_LENGTH)
            while chunk:
                log.debug("%s streaming DOWN %d bytes" % (self.sessionid, len(chunk)))
                yield chunk, ""
                chunk = response.read(MAX_PAYLOAD_LENGTH)            
        except GeneratorExit: 
            response.release()
            raise StopIteration 
        
    def meek_response(self, response, stream):
        if stream:
            return self._stream_response(response)
        data = response.read()
        response.release()
        if not data:
            return [("", "")]
        if not self.udpsock:
            return [(data, "")]
        
        # parse UDP packets 
        log.debug("%s DOWN %d bytes" % (self.sessionid, len(data)))
        lengths = get_meek_meta(response.headers, HEADER_UDP_PKTS).split(",")
        pos = 0
        pkts = []
        for length in lengths:
            nxt = pos + int(length)
            pkts.append((data[pos:nxt], ""))
            pos = nxt
        return pkts
        
    def meek_roundtrip(self, pkts):
        headers = {
            HEADER_SESSION_ID:  self.sessionid,
            HEADER_MSGTYPE:     MSGTYPE_DATA,
            'Host':             self.relay.hostname,
            'Content-Type':     "application/octet-stream",
            'Connection':       "Keep-Alive",
        }
        stream = False
        if not self.udpsock and "stream" in self.relay.properties:
            stream = True
            headers[HEADER_MODE] = MODE_STREAM
        
        if pkts and self.udpsock:
            lengths = str(",".join([str(len(p)) for p in pkts]))
            headers[HEADER_UDP_PKTS] = lengths
    
        data = "".join(pkts)
        headers['Content-Length'] = str(len(data))
        for _ in range(CLIENT_MAX_TRIES):
            try:
                log.debug("%s UP %d bytes" % (self.sessionid, len(data)))
                resp = self.httpclient.post("/", body=data, headers=headers)
                if resp.status_code != 200:  
                    # meek server always give 200, so all non-200s mean external issues. 
                    continue
                err = get_meek_meta(resp.headers, HEADER_ERROR)
                if err:
                    return [("", err)]
                else:
                    
                    try:
                        return self.meek_response(resp, stream)
                    except Exception as ex:
                        log.error("[Exception][meek_roundtrip - meek_response]: %s" % str(ex))
                        resp.release()
                        return [("", "Data Format Error")]
            except socket.timeout:  # @UndefinedVariable
                return [("", "timeout")]
            except Exception as ex:
                log.error("[Exception][meek_roundtrip]: %s" % str(ex))
                gevent.sleep(CLIENT_RETRY_DELAY)
        self.relay.failure += 1
        return [("", "Max Retry (%d) Exceeded" % CLIENT_MAX_TRIES)]
        
    def meek_sendrecv(self):
        pkts = []
        datalen = 0
        while not self.l2m_queue.empty():
            pkt = self.l2m_queue.get()
            pkts.append(pkt)
            datalen += len(pkt)
            if datalen >= MAX_PAYLOAD_LENGTH:
                for (resp, err) in self.meek_roundtrip(pkts):
                    yield (resp, err)
                    if err or not resp:
                        return
                    
                pkts = []
                datalen = 0
        for (resp, err) in self.meek_roundtrip(pkts):
            yield (resp, err)
            if err or not resp:
                return
                
    def meek_relay(self):
        for (resp, err) in self.meek_sendrecv():
            if err:
                return err
            if resp:
                self.m2l_queue.put(resp)
                self.l_notifier.set()
        return ""
                
    def meek_relay_thread(self):
        interval = CLIENT_INITIAL_POLL_INTERVAL
        while not self.finish.is_set():
            try:
                hasdata = self.m_notifier.wait(timeout=interval)
                self.m_notifier.clear()
                err = self.meek_relay() 
                if err:
                    break                
                if not hasdata:
                    interval *= CLIENT_POLL_INTERVAL_MULTIPLIER
                    if interval > CLIENT_MAX_POLL_INTERVAL:
                        interval = CLIENT_MAX_POLL_INTERVAL
            except Exception as ex:
                log.error("[Exception][meek_relay_thread]: %s" % str(ex))
                break
        self.finish.set()
        
    def write_to_client(self, data):
        if self.udpsock:
            self.udpsock.sendto(data, self.last_clientaddr)
        else:
            self.socksconn.sendall(data)
                
    def meek_write_to_client_thread(self):
        while not self.finish.is_set():
            try:
                hasdata = self.l_notifier.wait(timeout=CLIENT_MAX_POLL_INTERVAL)
                self.l_notifier.clear()
                if not hasdata:
                    self.timer.count(CLIENT_MAX_POLL_INTERVAL)
                    if self.timer.timeout():
                        break
                else:
                    self.timer.reset()
                    while not self.m2l_queue.empty():
                        data = self.m2l_queue.get()
                        if data:
                            self.write_to_client(data)
            except Exception as ex:
                log.error("[Exception][meek_write_to_client_thread]: %s" % str(ex))
                break
        self.finish.set()
        
    def read_from_client(self, timeout):
        readable, _, _ = select.select(self.allsocks, [], [], CLIENT_MAX_POLL_INTERVAL)
        if not readable:
            return None
        if self.socksconn in readable:
            if self.udpsock:
                raise RelaySessionError("unexcepted read-event from tcp socket in UDP session")
            data = self.socksconn.recv(MAX_PAYLOAD_LENGTH)
            if not data:
                raise RelaySessionError("peer closed")
            return data
        if self.udpsock and self.udpsock in readable:
            data, addr = self.udpsock.recvfrom(MAX_PAYLOAD_LENGTH)
            if not self.valid_udp_client(addr):
                return None
            else:
                self.last_clientaddr = addr
                return data
    
    def meek_read_from_client_thread(self):
        while not self.finish.is_set():
            try:
                data = self.read_from_client(CLIENT_MAX_POLL_INTERVAL)
                if not data:
                    self.timer.count(CLIENT_MAX_POLL_INTERVAL)
                    if self.timer.timeout():
                        break
                else:
                    self.timer.reset() 
                    self.l2m_queue.put(data)
                    self.m_notifier.set()
            except Exception as ex:
                log.error("[Exception][meek_read_from_client_thread]: %s" % str(ex))
                break
        self.finish.set()

    def proc_tcp_request(self, req):
        self.l2m_queue.put(req.pack())
    
    def relay_tcp(self):
        read_thread = gevent.spawn(self.meek_read_from_client_thread)
        write_thread = gevent.spawn(self.meek_write_to_client_thread)
        relay_thread = gevent.spawn(self.meek_relay_thread)
        # notify relay to send request
        self.m_notifier.set()
        [t.join() for t in (read_thread, write_thread, relay_thread)]
        log.info("Session %s Ended" % self.sessionid)
        
    def valid_udp_client(self, addr):
        if  self.client_associate[0] == "0.0.0.0" or \
                self.client_associate[0] == "::":
            return True
        if self.client_associate == addr:
            return True
        return False
        
    def cmd_udp_associate(self, req):
        self.client_associate = (req.dstaddr, req.dstport)
        self.last_clientaddr = self.client_associate
        for (resp, err) in self.meek_roundtrip([req.pack()]):
            if err:
                return
            if resp:
                Reply(resp)
        
        self.udpsock = bind_local_udp(self.socksconn)
        if not self.udpsock:
            request_fail(self.socksconn, req, GENERAL_SOCKS_SERVER_FAILURE)
            return
        self.track_sock(self.udpsock)
        
        read_thread = gevent.spawn(self.meek_read_from_client_thread)
        write_thread = gevent.spawn(self.meek_write_to_client_thread)
        relay_thread = gevent.spawn(self.meek_relay_thread)
        
        request_success(self.socksconn, *sock_addr_info(self.udpsock))
        [t.join() for t in (read_thread, write_thread, relay_thread)]
        log.info("Session %s Ended" % self.sessionid)
        
    def meek_terminate(self):
        headers = {
            HEADER_SESSION_ID:  self.sessionid,
            HEADER_MSGTYPE:     MSGTYPE_TERMINATE,
            #'Content-Type':     "application/octet-stream",
            'Content-Length':   "0",
            'Connection':       "Keep-Alive",
            'Host':             self.relay.hostname,
        }
        try:
            self.httpclient.post("/", data="", headers=headers)
        except:
            pass
    
    def clean(self):
        self.meek_terminate()
        for sock in self.allsocks:
            sock.close()
        #self.httpclient.close()
        self.conn_pool.release(self.relay, self.httpclient)
        
class MeekRelayFactory(RelayFactory):
    def __init__(self, relays, ca_certs, timeout=60):     
        self.relays = relays
        self.timeout = timeout
        self.ca_certs = ca_certs
        
    def set_relays(self, relays):
        self.relays = relays
        
    def select_relay(self):
        self.relays = [r for r in self.relays if r.failure < CLIENT_MAX_FAILURE]
        return random.choice(self.relays)
    
    def create_relay_session(self, socksconn, clientaddr):
        session = MeekSession(socksconn, self, self.timeout)
        log.info("Session %s created for connection from %s" % (session.sessionid, str(clientaddr)))
        return session
    
    
    