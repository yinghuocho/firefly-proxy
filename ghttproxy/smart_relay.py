import logging
from urlparse import urlparse
import re

from server import HTTPProxyServer, ProxyApplication, get_destination
from socks_relay import HTTP2SocksProxyApplication
from gsocks.smart_relay import RESocksMatcher, ForwardScheme

log = logging.getLogger(__name__)

class HTTP2SocksSmartApplication(ProxyApplication):
    def __init__(self, matcher, timeout=60):
        self.matcher = matcher
        self.timeout = timeout
        self.forwarders = {}
        self.register_forwarder("socks5", self.forward_socks5)
        
    def set_matcher(self, matcher):
        self.matcher = matcher
        
    def register_forwarder(self, scheme_name, forwarder):
        self.forwarders[scheme_name] = forwarder
        
    def find_forwarder(self, scheme_name):
        return self.forwarders.get(scheme_name, None)
        
    def forward_socks5(self, url, host, port, environ, start_response):
        app = HTTP2SocksProxyApplication(url.hostname, int(url.port))
        return app.application(environ, start_response)
        
    def forward(self, scheme, host, port, environ, start_response):
        forwarder = self.find_forwarder(scheme.name)
        if forwarder:
            return forwarder(scheme.data, host, port, environ, start_response)
        else:
            log.error("Unsupported forwarding scheme %s" % scheme.name)
            start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
            return ["Internal Server Error"]
        
    def application(self, environ, start_response):
        try:
            host, port = get_destination(environ)
        except Exception, e:
            log.error("[Exception][http]: %s" % str(e))
            start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8")])
            return ["Bad Request"]
        
        try:
            scheme = self.matcher.find(host, port)
            if not scheme:
                return super(HTTP2SocksSmartApplication, self).application(environ, start_response)
            else:
                return self.forward(scheme, host, port, environ, start_response) 
        except Exception, e:
            log.error("[Exception][application]: %s" % str(e))
            start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
            return ["Internal Server Error"]
        
if __name__ == '__main__':
    logging.basicConfig(
        format='[%(asctime)s][%(name)s][%(levelname)s] - %(message)s',
        datefmt='%Y-%d-%m %H:%M:%S',
        level=logging.DEBUG, 
    )
    scheme = ForwardScheme("socks5", urlparse('socks5://127.0.0.1:1080/'))
    rules = {
        (re.compile(r'.*\.whereisip\.net$'), re.compile(r'.*'), re.compile(r'.*')): scheme,
        (re.compile(r'.*google\.com$'), re.compile(r'.*'), re.compile(r'.*')): scheme,
    }
    matcher = RESocksMatcher(rules)
    HTTPProxyServer("127.0.0.1", 8000, HTTP2SocksSmartApplication(matcher)).run()     
        