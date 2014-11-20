import json
import fnmatch
import codecs
from urlparse import urlparse

from gsocks.match import ForwardMatch
from gsocks.smart_relay import SmartRelayFactory
from gsocks.server import SocksServer
from ghttproxy.smart_relay import HTTP2SocksSmartApplication
from ghttproxy.server import HTTPProxyServer

from lib.ipc import IPC_Process

class FireflyForwardMatch(ForwardMatch):
    def __init__(self, bl, blmeta, custom_bl, custom_wl, forward_url):
        self.forward_url = forward_url
        self.bl = set(bl)
        self.blmeta = blmeta
        self.custom_wl = custom_wl
        self.custom_bl = custom_bl
        
    def find(self, host, port, proto="tcp"):
        # first try white list
        for p in self.custom_wl:
            if fnmatch.fnmatch(host, p):
                return None
            
        # second try custom_bl
        for p in self.custom_bl:
            if fnmatch.fnmatch(host, p):
                return self.forward_url
            
        parts = host.split(".")
        for i in range(len(parts)-1, -1, -1):
            if ".".join(parts[i:]) in self.bl:
                return self.forward_url
        return None
    
def load_file(filename):
    f = codecs.open(filename, "r", "utf-8")
    data = [s.strip().encode("idna") for s in f.readlines()]
    data = [s for s in data if s and not s.startswith('#')]
    f.close()
    return data
    
def build_forward_match(bl_file, bl_meta, custom_bl_file, custom_wl_file, forward_url):
    bl = load_file(bl_file)
    custom_bl = load_file(custom_bl_file)
    custom_wl = load_file(custom_wl_file)
    f = codecs.open(bl_meta, "r", "utf-8")
    blmeta = json.loads(f.read())
    f.close()
    return FireflyForwardMatch(bl, blmeta, custom_bl, custom_wl, urlparse(forward_url))

class HTTPProxy(IPC_Process):
    timeout = 60
    
    def __init__(self, hub_ref, forward_match):
        super(HTTPProxy, self).__init__()
        self.hub_ref = hub_ref
        self.forward_match = forward_match
        confdata = self.hub_ref.get('confdata')
        self.proxy_ip = confdata['http_proxy_ip']
        self.proxy_port = confdata['http_proxy_port']
        
        self.process = None
        
    def run(self):
        self.application = HTTP2SocksSmartApplication(self.forward_match, self.timeout)
        self.proxy = HTTPProxyServer(self.proxy_ip, self.proxy_port, self.application, log=None)
        self.proxy.run()
        
    def IPC_update_forward_match(self, forward_match):
        self.forward_match = forward_match
        self.application.set_match(self.forward_match)
        
    def IPC_addr(self):
        return (str(self.proxy_ip), self.proxy_port)
    
    def IPC_url(self):
        return "http://%s:%d" % (str(self.proxy_ip), self.proxy_port)
        
class SocksProxy(IPC_Process):
    timeout = 60
    
    def __init__(self, hub_ref, forward_match):
        super(SocksProxy, self).__init__()
        self.hub_ref = hub_ref
        self.forward_match = forward_match
        self.process = None
        
        confdata = self.hub_ref.get('confdata')
        self.proxy_ip = confdata['socks_proxy_ip']
        self.proxy_port = confdata['socks_proxy_port']
        
        
    def run(self):
        self.relayfactory = SmartRelayFactory(self.forward_match, self.timeout)
        self.proxy = SocksServer(self.proxy_ip, self.proxy_port, self.relayfactory)
        self.proxy.run()
        
    def IPC_update_forward_match(self, forward_match):
        self.forward_match = forward_match
        self.relayfactory.set_match(self.forward_match)
        
    def IPC_addr(self):
        return (str(self.proxy_ip), self.proxy_port)
    
    def IPC_url(self):
        return "socks5://%s:%d" % (str(self.proxy_ip), self.proxy_port)
    
        
        
        