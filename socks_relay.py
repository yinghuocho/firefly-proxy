# a relay forward local socks to remote socks, 
import logging

from gevent import socket

from relay import RelayFactory, RelaySession, RelaySessionError
from utils import pipe_tcp, bind_local_udp, request_fail, send_request, \
sock_addr_info, read_reply, request_success, pipe_udp, read_init_request, \
read_init_reply, read_request
from msg import GENERAL_SOCKS_SERVER_FAILURE, UDP_ASSOCIATE, SUCCEEDED, \
CONNECT, BIND

log = logging.getLogger(__name__)

class SocksForwardSession(RelaySession):
    
    def __init__(self, socksconn, remoteconn):
        super(SocksForwardSession, self).__init__(socksconn)
        
        self.remoteconn = remoteconn
        self.track_sock(self.remoteconn)
        self.remotetimeout = self.remoteconn.gettimeout()
        self.client_associate = None
        self.last_clientaddr = None
        self.client2local_udpsock = None
        self.local2remote_udpsock = None
        
    def proc_tcp_request(self, req):
        self.remoteconn.sendall(req.pack())
        
    def relay_tcp(self):
        pipe_tcp(self.socksconn, self.remoteconn, self.timeout, self.remotetimeout)
        
    def proc_udp_request(self, req):
        self.client_associate = (req.dstaddr, req.dstport)
        self.last_clientaddr = self.client_associate
        self.client2local_udpsock = bind_local_udp(self.socksconn)
    
        self.local2remote_udpsock = bind_local_udp(self.remoteconn)
        if not self.client2local_udpsock or not self.local2remote_udpsock:
            request_fail(self.socksconn, req, GENERAL_SOCKS_SERVER_FAILURE)
            return False
        
        self.track_sock(self.client2local_udpsock)
        self.track_sock(self.local2remote_udpsock)
        send_request(self.remoteconn, UDP_ASSOCIATE, *sock_addr_info(self.local2remote_udpsock))
        reply = read_reply(self.remoteconn)
        if reply.rep != SUCCEEDED:
            return False
        
        self.remote_associate = (reply.bndaddr, reply.bndport)
        request_success(self.socksconn, *sock_addr_info(self.client2local_udpsock))
        return True
        
    def relay_udp(self):
        def addrchecker():
            def _(ip, port):
                if  self.client_associate[0] == "0.0.0.0" or \
                        self.client_associate[0] == "::":
                    return True
                if self.client_associate == (ip, port):
                    return True
                return False
            return _
        
        def c2r():
            def _(data, addr):
                self.last_clientaddr = addr
                return data, self.remote_associate
            return _
            
        def r2c():
            def _(data, addr):
                return data, self.last_clientaddr
            return _
            
        pipe_udp([self.socksconn, self.remoteconn],
            self.client2local_udpsock, self.local2remote_udpsock,
            self.timeout, self.remotetimeout,
            addrchecker(), c2r(), r2c())
    
    def cmd_udp_associate(self, req):
        if self.proc_udp_request(req):
            self.relay_udp()
    
    def process(self):
        try:
            initreq = read_init_request(self.socksconn)
            self.remoteconn.sendall(initreq.pack())
            initreply = read_init_reply(self.remoteconn)
            self.socksconn.sendall(initreply.pack())
            req = read_request(self.socksconn)
            {
                CONNECT: self.cmd_connect,
                BIND: self.cmd_bind,
                UDP_ASSOCIATE : self.cmd_udp_associate
            }[req.cmd](req)
            self.clean()
        except Exception, e:
            log.error("[Exception][SocksForwardSession]: %s" % str(e))
            self.clean()
    
class SocksForwardFactory(RelayFactory):
    """ forward to another socks.
    """
    def __init__(self, remoteip, remoteport, timeout=30):
        self.remoteip = remoteip
        self.remoteport = remoteport
        self.timeout = timeout
    
    def create_relay_session(self, socksconn, clientaddr):
        try:
            log.info("New socks connection from %s" % str(clientaddr))
            remoteconn = socket.create_connection((self.remoteip, self.remoteport), self.timeout)
            remoteconn.settimeout(self.timeout)
            return SocksForwardSession(socksconn, remoteconn)
        except socket.timeout, e:  # @UndefinedVariable
            log.error("[Exception][create_relay_session]: %s" % str(e))
            raise RelaySessionError("Remote Timeout.")
        
        