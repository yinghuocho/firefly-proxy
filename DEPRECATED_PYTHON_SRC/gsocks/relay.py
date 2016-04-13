# relay skeleton & normal socks relay
import logging
import time

from gevent import socket
from gevent import select

from utils import request_fail, basic_handshake_server, read_request, \
sock_addr_info, request_success, pipe_tcp, bind_local_udp, addr_info, \
bind_local_sock_by_addr, pipe_udp
from msg import CMD_NOT_SUPPORTED, CONNECT, BIND, UDP_ASSOCIATE, \
GENERAL_SOCKS_SERVER_FAILURE, UDPRequest

log = logging.getLogger(__name__)

class RelaySessionError(Exception): pass

class RelayFactory(object):
    def create_relay_session(self, socksconn, clientaddr):
        raise NotImplementedError
    
class RelaySession(object):
    def __init__(self, socksconn):
        self.socksconn = socksconn
        self.timeout = self.socksconn.gettimeout()
        self.allsocks = [self.socksconn]
        
    def track_sock(self, sock):
        # track all sockets so we know what to clean
        self.allsocks.append(sock)
        
    def cmd_bind(self, req):
        request_fail(self.socksconn, req, CMD_NOT_SUPPORTED)
    
    def proc_tcp_request(self, req):
        raise NotImplementedError
    
    def relay_tcp(self):
        raise NotImplementedError
    
    def cmd_connect(self, req):
        # TCP usually follows two steps.
        self.proc_tcp_request(req)
        self.relay_tcp()
    
    def cmd_udp_associate(self, req):
        # UDP is more specific
        raise NotImplementedError
    
    def process(self):
        try:
            if not basic_handshake_server(self.socksconn):
                self.clean()
                return
    
            req = read_request(self.socksconn)
            {
                CONNECT: self.cmd_connect,
                BIND: self.cmd_bind,
                UDP_ASSOCIATE : self.cmd_udp_associate
            }[req.cmd](req)
            self.clean()
        except Exception, e:
            log.error("[Exception][RelaySession]: %s" % str(e))
            self.clean()
    
    def clean(self):
        for sock in self.allsocks:
            if sock:
                sock.close()
    
class SocksSession(RelaySession):
    def __init__(self, socksconn):
        super(SocksSession, self).__init__(socksconn)
        
        self.remoteconn = None
        self.client_associate = None
        self.last_clientaddr = None
        self.client2local_udpsock = None
        self.local2remote_udpsock = None
       
    def proc_tcp_request(self, req):
        dst = (req.dstaddr, req.dstport)
        log.info("TCP request address: (%s:%d)" % dst)
        self.remoteconn = socket.create_connection(dst, self.timeout)
        self.track_sock(self.remoteconn)
        addrtype, bndaddr, bndport = sock_addr_info(self.remoteconn)
        request_success(self.socksconn, addrtype, bndaddr, bndport)
    
    def relay_tcp(self):
        pipe_tcp(self.socksconn, self.remoteconn, self.timeout, self.timeout)
            
    def proc_udp_request(self, req):
        self.client_associate = (req.dstaddr, req.dstport)
        log.info("UDP client adress: (%s:%d)" % self.client_associate)
        self.last_clientaddr = self.client_associate
        self.client2local_udpsock = bind_local_udp(self.socksconn)
        if not self.client2local_udpsock:
            request_fail(self.socksconn, req, GENERAL_SOCKS_SERVER_FAILURE)
            return False
        self.track_sock(self.client2local_udpsock)
        bndtype, bndaddr, bndport = sock_addr_info(self.client2local_udpsock)
        log.info("UDP ACCOSIATE: (%s:%d)" % (bndaddr, bndport))
        request_success(self.socksconn, bndtype, bndaddr, bndport)
        return True
        
    def wait_for_first_udp(self):
        # wait util first VALID packet come. 
        start = time.time()
        timeout = self.timeout
        while True:
            readable, _, _ = select.select([self.socksconn, self.client2local_udpsock], [], [], timeout)
            if not readable:
                raise socket.timeout("timeout")  # @UndefinedVariable
            if self.socksconn in readable:
                raise RelaySessionError("unexcepted read-event from tcp socket in UDP session")    
        
            timeout -= (time.time() - start)
            if timeout <= 0:
                raise socket.timeout("timeout")  # @UndefinedVariable
            data, addr = self.client2local_udpsock.recvfrom(65536)
            try:
                udpreq = UDPRequest(data)
                if udpreq.frag == '\x00':
                    return data, addr
            except:
                pass
        
    def relay_udp(self, firstdata, firstaddr):
        def addrchecker():
            def _(ip, port):
                if  self.client_associate[0] == "0.0.0.0" or \
                        self.client_associate[0] == "::":
                    return True
                if self.client_associate == (ip, port):
                    return True
                log.info("UDP packet dropped for invalid address.")
                return False
            return _
        
        def c2r():
            def _(data, addr):
                self.last_clientaddr = addr
                try:
                    udpreq = UDPRequest(data)
                    if udpreq.frag != '\x00':
                        return None, None
                    return udpreq.data, (udpreq.dstaddr, udpreq.dstport)
                except Exception, e:
                    log.error("[relay_udp][c2r] Exception: %s", str(e))
                    return None, None
            return _
            
        def r2c():
            def _(data, addr):
                addrtype, dstaddr, dstport = addr_info(addr)
                udpreq = UDPRequest(addrtype=addrtype, dstaddr=dstaddr, dstport=dstport, data=data)
                return udpreq.pack(), self.last_clientaddr
            return _
        
        data, dst = c2r()(firstdata, firstaddr)
        self.local2remote_udpsock = bind_local_sock_by_addr(dst)
        self.track_sock(self.local2remote_udpsock)
        self.local2remote_udpsock.send(data)
        pipe_udp([self.socksconn],
            self.client2local_udpsock, self.local2remote_udpsock,
            self.timeout, self.timeout,
            addrchecker(), c2r(), r2c())
        
    def cmd_udp_associate(self, req):
        if self.proc_udp_request(req):
            firstdata, firstaddr = self.wait_for_first_udp()
            self.relay_udp(firstdata, firstaddr)
    
class SocksRelayFactory(RelayFactory):
    def create_relay_session(self, socksconn, clientaddr):
        log.info("New socks connection from %s" % str(clientaddr))
        return SocksSession(socksconn)
    
