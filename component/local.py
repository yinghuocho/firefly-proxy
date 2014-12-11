import logging
import fnmatch
import codecs
import urlparse
from httplib import HTTPConnection
import mimetools
from StringIO import StringIO

from gevent import socket

from gsocks.smart_relay import SmartRelayFactory, ForwardScheme, ForwardMatcher, SmartRelaySession
from gsocks.server import SocksServer
from gsocks.utils import request_success, sock_addr_info, pipe_tcp
from gsocks.msg import UDPRequest, IP_V4
from ghttproxy.smart_relay import HTTP2SocksSmartApplication
from ghttproxy.server import HTTPProxyServer, copy_request, set_forwarded_for, CHUNKSIZE

from lib.ipc import IPC_Process
from lib.utils import init_logging

log = logging.getLogger(__name__)

class FireflyHosts(object):
    def __init__(self, hosts_entries, groups, disabled_groups):
        self.groups = groups
        self.disabled = set(disabled_groups)
        self.data = {}
        for entry in hosts_entries:
            try:
                addr, name = [s.strip() for s in entry.split()]
                # TODO: support IPv6 
                socket.inet_aton(addr)  # @UndefinedVariable
                self.data[name.encode("idna")] = ForwardScheme("hosts", [addr])
            except:
                pass
            
    def domain_count(self):
        return len(self.data.keys())
            
    def disable(self, groupname):
        self.disabled.add(groupname)
        
    def need_redirect(self, method, host):
        if method != "GET":
            return False
        
        for (_, domains) in self.groups.iteritems():
            for (domain, flag) in domains:
                parts = host.split(".")
                for i in range(len(parts)-1, -1, -1):
                    if ".".join(parts[i:]) == domain and flag:
                        print "%s needs to be redirected to HTTPS." % host
                        return True
        return False
            
    def is_disabled(self, host):
        for groupname in self.disabled:
            domains = self.groups.get(groupname, [])
            for (domain, _) in domains:
                parts = host.split(".")
                for i in range(len(parts)-1, -1, -1):
                    if ".".join(parts[i:]) == domain:
                        return True
        return False
            
    def find(self, host):
        for name, addr in self.data.iteritems():
            if name == host and not self.is_disabled(host):
                return addr
        return None
            
class FireflyForwardMatcher(ForwardMatcher):
    def __init__(self, bl, hosts, custom_bl, custom_wl, forward_url):
        self.socks5_scheme = ForwardScheme("socks5", forward_url)
        self.bl = set(bl)
        self.custom_wl = custom_wl
        self.custom_bl = custom_bl
        self.hosts = hosts
        
    def find(self, host, port, proto="tcp"):
        # 0. try hosts data
        addr = self.hosts.find(host)
        if addr:
            return addr
        
        # 1. try white list
        for p in self.custom_wl:
            if fnmatch.fnmatch(host, p):
                return None
            
        # 2. try custom_bl
        for p in self.custom_bl:
            if fnmatch.fnmatch(host, p):
                return self.socks5_scheme
            
        parts = host.split(".")
        for i in range(len(parts)-1, -1, -1):
            if ".".join(parts[i:]) in self.bl:
                return self.socks5_scheme
        return None
    
    def need_redirect(self, method, host):
        return self.hosts.need_redirect(method, host)
    
def load_file(filename, idna=True):
    f = codecs.open(filename, "r", "utf-8")
    data = [s.strip() for s in f.readlines()]
    data = [s for s in data if s and not s.startswith('#')]
    if idna:
        data = [s.encode("idna") for s in data]
    f.close()
    return data
    
def create_forward_matcher(bl_file, custom_bl_file, custom_wl_file, forward_url, 
        hosts_file, hosts_groups, hosts_disabled_groups):
    bl = load_file(bl_file)
    custom_bl = load_file(custom_bl_file)
    custom_wl = load_file(custom_wl_file)
    
    hosts_entris = load_file(hosts_file, idna=False)
    hosts = FireflyHosts(hosts_entris, hosts_groups, hosts_disabled_groups)
    
    return FireflyForwardMatcher(bl, hosts, custom_bl, custom_wl, urlparse.urlparse(forward_url))

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
            # no IPv6 ?
            http_conn = socket.create_connection((addrs[0], port), timeout=self.timeout)
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
        
    def forward_hosts_https(self, addrs, host, port, environ, start_response):
        try:
            https_conn = socket.create_connection((addrs[0], port), timeout=self.timeout)
            environ['HTTPS_CONN'] = https_conn
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
            return self.forward_hosts_https(addrs, host, port, environ, start_response)
        else:
            return self.forward_hosts_http(addrs, host, port, environ, start_response)

class HTTPProxy(IPC_Process):
    timeout = 60
    
    def __init__(self, hub_ref, forward_matcher):
        super(HTTPProxy, self).__init__()
        self.hub_ref = hub_ref
        self.forward_matcher = forward_matcher
        confdata = self.hub_ref.get('confdata')
        self.proxy_ip = confdata['http_proxy_ip']
        self.proxy_port = confdata['http_proxy_port']
        
        self.process = None
        
    def run(self):
        init_logging()
        self.application = FireflyHTTPApplication(self.forward_matcher, self.timeout)
        self.proxy = HTTPProxyServer(self.proxy_ip, self.proxy_port, self.application, log=None)
        self.proxy.run()
        
    def IPC_update_forward_matcher(self, forward_matcher):
        self.forward_matcher = forward_matcher
        self.application.set_matcher(self.forward_matcher)
        
    def IPC_addr(self):
        return (str(self.proxy_ip), self.proxy_port)
    
    def IPC_url(self):
        return "http://%s:%d" % (str(self.proxy_ip), self.proxy_port)
    
class FireflyRelaySession(SmartRelaySession):
    def __init__(self, *args, **kwargs):
        super(FireflyRelaySession, self).__init__(*args, **kwargs)
        self.register_forwarder("hosts", "tcp", self.forward_hosts_tcp)
        self.register_forwarder("hosts", "udp", self.forward_hosts_udp)

    def forward_hosts_tcp(self, addrs, req):
        # no IPv6 ?
        self.remoteconn = socket.create_connection((addrs[0], req.dstport), self.timeout)
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
        # no IPv6
        orig_req = UDPRequest(firstdata)
        new_req = UDPRequest(
            rsv      = orig_req.rsv, 
            frag     = orig_req.frag, 
            dstport  = orig_req.dstport,
            dstaddr  = addrs[0],
            addrtype = IP_V4,
            data     = orig_req.data
        )
        localhandler.relay_udp(new_req.pack(), firstaddr)

class FireflyRelayFactory(SmartRelayFactory):
    def create_relay_session(self, socksconn, clientaddr):
        return FireflyRelaySession(socksconn, self.timeout, self.matcher)
        
class SocksProxy(IPC_Process):
    timeout = 60
    
    def __init__(self, hub_ref, forward_matcher):
        super(SocksProxy, self).__init__()
        self.hub_ref = hub_ref
        self.forward_matcher = forward_matcher
        self.process = None
        
        confdata = self.hub_ref.get('confdata')
        self.proxy_ip = confdata['socks_proxy_ip']
        self.proxy_port = confdata['socks_proxy_port']
        
    def run(self):
        init_logging()
        self.relayfactory = FireflyRelayFactory(self.forward_matcher, self.timeout)
        self.proxy = SocksServer(self.proxy_ip, self.proxy_port, self.relayfactory)
        self.proxy.run()
        
    def IPC_update_forward_matcher(self, forward_matcher):
        self.forward_matcher = forward_matcher
        self.relayfactory.set_matcher(self.forward_matcher)
        
    def IPC_addr(self):
        return (str(self.proxy_ip), self.proxy_port)
    
    def IPC_url(self):
        return "socks5://%s:%d" % (str(self.proxy_ip), self.proxy_port)
    
        
        
        