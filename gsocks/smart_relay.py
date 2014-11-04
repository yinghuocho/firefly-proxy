# a relay with policy based forwarding.
import logging
import re

from gevent import socket
from urlparse import urlparse

from relay import SocksSession, RelayFactory, RelaySession
from socks_relay import SocksForwardSession
from utils import *
from msg import *

log = logging.getLogger(__name__)

class SmartRelayError(Exception): pass

class SmartRelaySession(RelaySession):
    def __init__(self, socksconn, timeout, match):
        super(SmartRelaySession, self).__init__(socksconn)
        
        self.match = match
        self.handler = None
        
    def forward_handshake(self, socksconn):
        initreq = InitRequest()
        socksconn.sendall(initreq.pack())
        initreply = read_init_reply(socksconn)
        if initreply.method != NO_AUTHENTICATION_REQUIRED:
            return False
        return True
        
    def smart_socks_tcp( self, forwardurl, req):
        remoteconn = socket.create_connection((forwardurl.hostname, forwardurl.port), self.timeout)
        remoteconn.settimeout(self.timeout)
        handler = SocksForwardSession(self.socksconn, remoteconn)
        self.handler = handler
        
        # handshake, send request, then start to pipe
        if self.forward_handshake(handler.remoteconn):
            handler.proc_tcp_request(req)
            handler.relay_tcp()
            
    def cmd_connect(self, req):
        url = self.match.find(req.dstaddr, req.dstport, proto="tcp")
        if not url:
            # no rule found, go as local socks proxy 
            handler = SocksSession(self.socksconn)
            self.handler = handler
            handler.proc_tcp_request(req)
            handler.relay_tcp()
        else:
            if url.scheme != 'socks5':
                raise SmartRelayError("forward url %s not supported" % str(url))
            self.smart_socks_tcp(url, req)
        
    def smart_socks_udp(self, forwardurl, local_handler, firstdata, firstaddr):
        remoteconn = socket.create_connection((forwardurl.hostname, forwardurl.port), self.timeout)
        remoteconn.settimeout(self.timeout)
        handler = SocksForwardSession(self.socksconn, remoteconn)
        
        # copy already-exist states from previous handler
        handler.client_associate = local_handler.client_associate
        handler.last_clientaddr = local_handler.last_clientaddr
        handler.client2local_udpsock = local_handler.client2local_udpsock
        handler.track_sock(handler.client2local_udpsock)
        self.handler = handler
        
        # handshake, then request-reply, then send first packet, finally start to pipe
        if self.forward_handshake(handler.remoteconn):
            handler.local2remote_udpsock = bind_local_udp(handler.remoteconn)
            handler.track_sock(handler.local2remote_udpsock)
            send_request(handler.remoteconn, UDP_ASSOCIATE, *sock_addr_info(handler.local2remote_udpsock))
            reply = read_reply(handler.remoteconn)
            if reply.rep != SUCCEEDED:
                return           
            handler.remote_associate = (reply.bndaddr, reply.bndport)
            handler.last_clientaddr = firstaddr
            handler.local2remote_udpsock.sendto(firstdata, handler.remote_associate)
            handler.relay_udp() 
        
    def cmd_udp_associate(self, req):
        local_handler = SocksSession(self.socksconn)
        self.handler = local_handler
        if local_handler.proc_udp_request(req):
            # a UDP session is determined by first UDP packet
            firstdata, firstaddr = local_handler.wait_for_first_udp()
            url = self.match.find(firstaddr[0], firstaddr[1], proto="udp")
            if not url:
                # no rule found, go as local socks proxy 
                local_handler.relay_udp(firstdata, firstaddr)    
            else:
                if url.scheme != 'socks5':
                    raise SmartRelayError("forward url %s not supported" % str(url))            
                self.smart_socks_udp(url, local_handler, firstdata, firstaddr)
            
    def clean(self):
        super(SmartRelaySession, self).clean()
        if self.handler:
            self.handler.clean()

class SmartRelayFactory(RelayFactory):
    def __init__(self, match, timeout=30):
        self.match = match
        self.timeout = timeout
        
    def set_match(self, match):
        self.match = match
        
    def create_relay_session(self, socksconn, clientaddr):
        return SmartRelaySession(socksconn, self.timeout, self.match)
    
    