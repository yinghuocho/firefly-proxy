import logging
import urlparse
from httplib import HTTPConnection

from gevent import socket

from server import HTTPProxyServer, ProxyApplication, \
copy_request, CHUNKSIZE, get_destination, set_forwarded_for
from gsocks import utils as socksutils
from gsocks import msg as socksmsg

log = logging.getLogger(__name__)

class HTTP2SocksProxyApplication(ProxyApplication):
    def __init__(self, socksip, socksport, timeout=60):
        super(HTTP2SocksProxyApplication, self).__init__(timeout)
        
        self.socksip = socksip
        self.socksport = socksport
    
    def connect_socks(self, host, port):
        socksconn = None
        try:
            socksconn = socket.create_connection((self.socksip, self.socksport), timeout=self.timeout)
            if not socksutils.basic_handshake_client(socksconn):
                socksconn.close()
            addrtype = socksutils.addr_type(host)
            socksutils.send_request(socksconn, cmd=socksmsg.CONNECT,
                        addrtype=addrtype, dstaddr=host, dstport=port)
            reply = socksutils.read_reply(socksconn)
            if reply.rep != socksmsg.SUCCEEDED:
                log.info("error response %d returned from socks server" % reply.rep)
                socksconn.close()
                return None
            return socksconn
        except Exception, e:
            log.error("[Exception][connect_socks]: %s" % str(e))
            if socksconn:
                socksconn.close()
            return None

    def tunnel(self, environ, start_response):
        try:
            host, port = get_destination(environ)
        except Exception, e:
            log.error("[Exception][tunnel]: %s" % str(e))
            start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8")])
            return ["Bad Request"]
        
        socksconn = self.connect_socks(host, port)
        if not socksconn:
            start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
            return ["Internal Server Error"]
        else:
            environ['TUNNEL_CONN'] = socksconn
            start_response("200 Connection Established", [])
            return []
        
    def http(self, environ, start_response):
        try:
            method, url, body, headers = copy_request(environ)
            host, port = get_destination(environ)
        except Exception, e:
            log.error("[Exception][http]: %s" % str(e))
            start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8")])
            yield "Bad Request"
            return
        
        socksconn = self.connect_socks(host, port)
        if not socksconn:
            start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
            yield "Internal Server Error"
            return
        
        try:
            conn = HTTPConnection(host, port=port)
            conn.sock = socksconn
            set_forwarded_for(environ, headers)
            u = urlparse.urlsplit(url)
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
            log.error("[Exception][http]: %s" % str(e))
            start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
            yield "Internal Server Error"
            return
        
if __name__ == '__main__':
    logging.basicConfig(
        format='[%(asctime)s][%(name)s][%(levelname)s] - %(message)s',
        datefmt='%Y-%d-%m %H:%M:%S',
        level=logging.DEBUG, 
    )
    HTTPProxyServer("127.0.0.1", 8000,
        HTTP2SocksProxyApplication("127.0.0.1", 1080)).run()

