# a relay with policy based forwarding.
import logging
import re

from gevent import socket

from relay import SocksSession, RelayFactory, RelaySession
from socks_relay import SocksForwardSession

import msg
import utils

log = logging.getLogger(__name__)

class ForwardDestination(object):
    def __init__(self, scheme, data):
        self.scheme = scheme
        self.data = data
    
    def __repr__(self):
        return "<%s:%r>" % (self.scheme, self.data)

class ForwardMatcher(object):
    def find(self, host, port, proto="tcp"):
        # return a list of ForwardScheme objects
        return None
    
class RESocksMatcher(ForwardMatcher):
    def __init__(self, rules):
        self.rules = rules
        
    def find(self, host, port, proto="tcp"):
        for (pattern, dst) in self.rules.iteritems():
            (h, p, pr) = pattern
            if re.match(pr, proto) and re.match(h, host.rstrip(".")) \
                        and re.match(p, str(port)):
                log.info("forward rule %s found for %s:%d:%s" % (dst, host, port, proto))
                return dst
        return None

class SmartRelayError(Exception): pass

class SmartRelaySession(RelaySession):
    def __init__(self, socksconn, timeout, matcher):
        super(SmartRelaySession, self).__init__(socksconn)
        self.forwarders = {}
        self.matcher = matcher
        self.handler = None
        self.register_forwarder("socks5", "tcp", self.forward_socks5_tcp)
        self.register_forwarder("socks5", "udp", self.forward_socks5_udp)
        
    def register_forwarder(self, scheme, proto, forwarder):
        self.forwarders["_".join([scheme, proto])] = forwarder
        
    def find_forwarder(self, scheme, proto):
        return self.forwarders.get("_".join([scheme, proto]), None)
        
    def forward_socks5_handshake(self, socksconn):
        initreq = msg.InitRequest()
        socksconn.sendall(initreq.pack())
        initreply = utils.read_init_reply(socksconn)
        if initreply.method != msg.NO_AUTHENTICATION_REQUIRED:
            return False
        return True
        
    def forward_socks5_tcp(self, url, req):
        remoteconn = socket.create_connection((url.hostname, url.port), self.timeout)
        remoteconn.settimeout(self.timeout)
        handler = SocksForwardSession(self.socksconn, remoteconn)
        self.handler = handler
        # handshake, send request, then start to pipe
        if self.forward_socks5_handshake(handler.remoteconn):
            handler.proc_tcp_request(req)
            handler.relay_tcp()
        return True
            
    def forward_socks5_udp(self, url, localhandler, firstdata, firstaddr):
        remoteconn = socket.create_connection((url.hostname, url.port), self.timeout)
        remoteconn.settimeout(self.timeout)
        handler = SocksForwardSession(self.socksconn, remoteconn)
        # copy already-exist states from local handler
        handler.client_associate = localhandler.client_associate
        handler.last_clientaddr = localhandler.last_clientaddr
        handler.client2local_udpsock = localhandler.client2local_udpsock
        handler.track_sock(handler.client2local_udpsock)
        self.handler = handler
        
        # handshake, then request-reply, then send first packet, finally start to pipe
        if self.forward_socks5_handshake(handler.remoteconn):
            handler.local2remote_udpsock = utils.bind_local_udp(handler.remoteconn)
            handler.track_sock(handler.local2remote_udpsock)
            utils.send_request(handler.remoteconn, msg.UDP_ASSOCIATE, *utils.sock_addr_info(handler.local2remote_udpsock))
            reply = utils.read_reply(handler.remoteconn)
            if reply.rep != msg.SUCCEEDED:
                return False           
            handler.remote_associate = (reply.bndaddr, reply.bndport)
            handler.last_clientaddr = firstaddr
            handler.local2remote_udpsock.sendto(firstdata, handler.remote_associate)
            handler.relay_udp()
        return True
    
    def forward_tcp(self, dst, req):
        forwarder = self.find_forwarder(dst.scheme, "tcp")
        if forwarder:
            forwarder(dst.data, req)
        else:            
            raise SmartRelayError("forward scheme %s not supported" % dst.scheme)
            
    def forward_udp(self, dst, localhandler, firstdata, firstaddr):
        forwarder = self.find_forwarder(dst.scheme, "udp")
        if forwarder:
            forwarder(dst.data, localhandler, firstdata, firstaddr)
        else:            
            raise SmartRelayError("forward scheme %s not supported" % dst.scheme)
            
    def cmd_connect(self, req):
        dst = self.matcher.find(req.dstaddr, req.dstport, proto="tcp")
        if not dst:
            # no forward schemes found, go as local socks proxy 
            handler = SocksSession(self.socksconn)
            self.handler = handler
            handler.proc_tcp_request(req)
            handler.relay_tcp()
        else:
            self.forward_tcp(dst, req)
            
    def cmd_udp_associate(self, req):
        handler = SocksSession(self.socksconn)
        self.handler = handler
        if handler.proc_udp_request(req):
            # a UDP session is determined by first UDP packet
            firstdata, firstaddr = handler.wait_for_first_udp()
            scheme = self.matcher.find(firstaddr[0], firstaddr[1], proto="udp")
            if not scheme:
                # no forward schemes found, go as local socks proxy 
                handler.relay_udp(firstdata, firstaddr)    
            else:
                self.forward_udp(scheme, handler, firstdata, firstaddr)
                    
    def clean(self):
        super(SmartRelaySession, self).clean()
        if self.handler:
            self.handler.clean()

class SmartRelayFactory(RelayFactory):
    def __init__(self, matcher, timeout=30):
        self.matcher = matcher
        self.timeout = timeout
        
    def set_matcher(self, matcher):
        self.matcher = matcher
        
    def create_relay_session(self, socksconn, clientaddr):
        return SmartRelaySession(socksconn, self.timeout, self.matcher)
    
    