import logging
import urlparse
import re

from server import HTTPProxyServer, ProxyHandler, ProxyApplication, get_destination
from socks_relay import HTTP2SocksProxyApplication
from gsocks.match import ForwardMatch

log = logging.getLogger(__name__)
    
class HTTPForwardRegexMatch(ForwardMatch):
    def __init__(self, rules):
        self.rules = rules
        
    def find(self, host, port, proto="tcp"):
        for (pattern, forward) in self.rules.iteritems():
            (h, p) = pattern
            if re.match(h, host.rstrip(".")) and re.match(p, str(port)):
                log.info("forward %s found for %s:%d" % (forward, host, port))
                return forward
        return None

class HTTP2SocksSmartApplication(ProxyApplication):
    def __init__(self, match, timeout=60):
        self.match = match
        self.timeout = timeout
        
    def set_match(self, match):
        self.match = match
        
    def application(self, environ, start_response):
        try:
            host, port = get_destination(environ)
        except Exception, e:
            log.error("[Exception][http]: %s" % str(e))
            start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8")])
            return ["Bad Request"]
        
        try:
            dst = self.match.find(host, port)
            if not dst:
                return super(HTTP2SocksSmartApplication, self).application(environ, start_response)
            if dst.scheme != 'socks5':
                log.error("Unsupported forwarding scheme %s" % dst.scheme)
                start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
                return ["Internal Server Error"]
            else:
                app = HTTP2SocksProxyApplication(dst.hostname, int(dst.port))
                return app.application(environ, start_response)
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
    rules = {
        (re.compile(r'.*\.whereisip\.net$'), re.compile(r'.*')): urlparse.urlparse('socks5://127.0.0.1:1080/'),
        (re.compile(r'.*google\.com$'), re.compile(r'.*')): urlparse.urlparse('socks5://127.0.0.1:1080/'),
    }
    match = HTTPForwardRegexMatch(rules)
    HTTPProxyServer("127.0.0.1", 8000,
        HTTP2SocksSmartApplication(match)).run()     
        