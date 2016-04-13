import logging
import urlparse
from httplib import HTTPConnection
import mimetools
from StringIO import StringIO

from gevent import socket

from gsocks.smart_relay import SmartRelayFactory, SmartRelaySession
from gsocks.server import SocksServer
from gsocks.utils import request_success, sock_addr_info, pipe_tcp
from gsocks.msg import UDPRequest, IP_V4, IP_V6
from ghttproxy.smart_relay import HTTP2SocksSmartApplication
from ghttproxy.server import HTTPProxyServer, copy_request, set_forwarded_for, CHUNKSIZE

from component.hosts import create_connection_hosts
from lib.ipc import ActorProcess
from lib.utils import init_logging

log = logging.getLogger(__name__)

class FireflyHTTPApplication(HTTP2SocksSmartApplication):
    def __init__(self, *args, **kwargs):
        super(FireflyHTTPApplication, self).__init__(*args, **kwargs)
        self.register_forwarder("hosts", self.forward_hosts)
        
    def forward_hosts_http(self, addrs, host, port, environ, start_response):
        try:
            method, url, body, headers = copy_request(environ)
        except:
            start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8")])
            yield "Bad Request"
            return
        
        try:
            u = urlparse.urlsplit(url)
            if self.matcher.need_redirect(method, host):
                start_response(
                    "%d %s" % (301, "Moved Permanently"), [
                        ("Location", urlparse.urlunsplit(("https", u.netloc, u.path, u.query, u.fragment))),
                        ("Connection", "close"),
                    ],
                )
                yield ""
                return            
            
            set_forwarded_for(environ, headers)
            http_conn = create_connection_hosts(addrs, port, self.timeout)
            conn = HTTPConnection(host, port=port)
            conn.sock = http_conn
            
            path = urlparse.urlunsplit(("", "", u.path, u.query, ""))
            conn.request(method, path, body, headers)
            resp = conn.getresponse()
            start_response("%d %s" % (resp.status, resp.reason), resp.getheaders())
            while True:
                data = resp.read(CHUNKSIZE)
                if not data:
                    break
                yield data
            conn.close()
        except Exception, e:
            log.error("[Exception][FireflyHTTPApplication.forward_hosts_http]: %s" % str(e))
            start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
            yield "Internal Server Error"
            return
        
    def forward_hosts_tunnel(self, addrs, host, port, environ, start_response):
        try:
            tunnel_conn = create_connection_hosts(addrs, port, self.timeout)
            environ['TUNNEL_CONN'] = tunnel_conn
            start_response("200 Connection established", [])
            return []
        except socket.timeout:  # @UndefinedVariable
            start_response("504 Gateway Timeout", [("Content-Type", "text/plain; charset=utf-8")])
            return ["Gateway Timeout"]
        except:
            start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
            return ["Internal Server Error"]
        
    def forward_hosts(self, addrs, host, port, environ, start_response):
        if environ["REQUEST_METHOD"] == "CONNECT":
            return self.forward_hosts_tunnel(addrs, host, port, environ, start_response)
        else:
            return self.forward_hosts_http(addrs, host, port, environ, start_response)

class HTTPProxy(ActorProcess):
    timeout = 60
    
    def __init__(self, coordinator, matcher):
        super(HTTPProxy, self).__init__()
        self.coordinator = coordinator
        self.matcher = matcher
        
        confdata = self.coordinator.get('confdata')
        self.ip = confdata['http_proxy_ip']
        self.port = confdata['http_proxy_port']
        
    def run(self):
        init_logging()
        self.application = FireflyHTTPApplication(self.matcher, self.timeout)
        self.proxy = HTTPProxyServer(self.ip, self.port, self.application, log=None)
        self.proxy.run()
        
    def IPC_addr(self):
        return (self.ip, self.port)
    
    def IPC_url(self):
        return "http://%s:%d" % (str(self.ip), self.port)
    
    def IPC_update_matcher(self, matcher):
        self.matcher = matcher
        self.application.set_matcher(matcher)
        
class FireflyRelaySession(SmartRelaySession):
    def __init__(self, *args, **kwargs):
        super(FireflyRelaySession, self).__init__(*args, **kwargs)
        self.register_forwarder("hosts", "tcp", self.forward_hosts_tcp)
        self.register_forwarder("hosts", "udp", self.forward_hosts_udp)

    def forward_hosts_tcp(self, addrs, req):
        self.remoteconn = create_connection_hosts(addrs, req.dstport, self.timeout)
        self.track_sock(self.remoteconn)
        addrtype, bndaddr, bndport = sock_addr_info(self.remoteconn)
        request_success(self.socksconn, addrtype, bndaddr, bndport)
        data = self.socksconn.recv(65536)
        if data[:3] == 'GET':
            request, rest = data.split('\r\n', 1)
            method, path, version = request.split()
            headers = mimetools.Message(StringIO(rest))
            host = headers.getheader("host", "")
            if self.matcher.need_redirect(method, host):
                response = [
                    "%s 301 Moved Permanently" % version,
                    "Location: https://%s" % "".join([host, path]),
                    "Connection: close",
                    "",
                    ""
                ]
                self.socksconn.sendall("\r\n".join(response))
            else:
                self.remoteconn.sendall(data)
                pipe_tcp(self.socksconn, self.remoteconn, self.timeout, self.timeout)
        else:
            self.remoteconn.sendall(data)
            pipe_tcp(self.socksconn, self.remoteconn, self.timeout, self.timeout)
    
    def forward_hosts_udp(self, addrs, localhandler, firstdata, firstaddr):
        orig_req = UDPRequest(firstdata)
        new_req = UDPRequest(
            rsv=orig_req.rsv,
            frag=orig_req.frag,
            dstport=orig_req.dstport,
            dstaddr=addrs[0],
            addrtype=IP_V6 if ":" in addrs[0] else IP_V4,
            data=orig_req.data
        )
        localhandler.relay_udp(new_req.pack(), firstaddr)

class FireflyRelayFactory(SmartRelayFactory):
    def create_relay_session(self, socksconn, clientaddr):
        return FireflyRelaySession(socksconn, self.timeout, self.matcher)
        
class SocksProxy(ActorProcess):
    timeout = 60
    
    def __init__(self, coordinator, matcher):
        super(SocksProxy, self).__init__()
        self.coordinator = coordinator
        self.matcher = matcher
        
        confdata = self.coordinator.get('confdata')
        self.ip = confdata['socks_proxy_ip']
        self.port = confdata['socks_proxy_port']
        
    def run(self):
        init_logging()
        self.relayfactory = FireflyRelayFactory(self.matcher, self.timeout)
        self.proxy = SocksServer(self.ip, self.port, self.relayfactory)
        self.proxy.run()
        
    def IPC_addr(self):
        return (self.ip, self.port)
    
    def IPC_update_matcher(self, matcher):
        self.matcher = matcher
        self.relayfactory.set_matcher(matcher)
        
    def IPC_url(self):
        return "socks5://%s:%d" % (str(self.ip), self.port)
        
        
