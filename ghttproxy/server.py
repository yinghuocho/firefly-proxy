import logging
import urlparse
import time
from httplib import HTTPConnection

import gevent
from gevent import socket
from gevent.pywsgi import WSGIHandler, WSGIServer
from gevent.pool import Pool
from gevent.event import Event

log = logging.getLogger(__name__)

CHUNKSIZE = 65536

def pipe_socket(client, remote):
    def copy(a, b, finish):
        while not finish.is_set():
            try:
                data = a.recv(CHUNKSIZE)
                if not data:
                    break
                b.sendall(data)
            except:
                break
        finish.set()
        
    finish = Event()
    finish.clear()
    threads = [
        gevent.spawn(copy, client, remote, finish),
        gevent.spawn(copy, remote, client, finish),
    ]
    [t.join() for t in threads]
    client.close()
    remote.close()

class ProxyHandler(WSGIHandler):
    """ override WSGIHandler.handle() to process https proxy
    """
    def handle(self):
        try:
            while self.socket is not None:
                self.time_start = time.time()
                self.time_finish = 0
                result = self.handle_one_request()
                if result is None:
                    break
                if result is True:
                    if self.command == "CONNECT":
                        break
                    else:
                        continue
                self.status, response_body = result
                self.socket.sendall(response_body)
                if self.time_finish == 0:
                    self.time_finish = time.time()
                self.log_request()
                break
            
            if self.socket and hasattr(self, 'command') and \
                        self.command == "CONNECT" and self.environ.get('TUNNEL_CONN', None):
                pipe_socket(self.socket, self.environ.get('TUNNEL_CONN'))
        finally:
            if self.socket is not None:
                try:
                    try:
                        self.socket._sock.recv(16384)
                    finally:
                        self.socket._sock.close()  
                        self.socket.close()
                except socket.error:  # @UndefinedVariable
                    pass
            self.__dict__.pop('socket', None)
            self.__dict__.pop('rfile', None)

# some of below code are copied and modifed from "meek/wsgi/reflect.py" 
# at https://git.torproject.org/pluggable-transports/meek.git

# Limits a file-like object to reading only n bytes. Used to keep limit
# wsgi.input to the Content-Length, otherwise it blocks.
class LimitedReader(object):
    def __init__(self, f, n):
        self.f = f
        self.n = n

    def __getattr__(self, name):
        return getattr(self.f, name)

    def read(self, size=None):
        if self.n <= 0:
            return ""
        if size is not None and size > self.n:
            size = self.n
        data = self.f.read(size)
        self.n -= len(data)
        return data
    
def set_forwarded_for(environ, headers):
    if environ['REMOTE_ADDR'] in ('127.0.0.1', '::1') and \
            'X-Forwarded-For' not in headers:
        # don't add header if we are forwarding localhost, 
        return
    ips = headers.get('X-Forwarded-For', '').split(", ")
    ips.append(environ['REMOTE_ADDR'])
    headers['X-Forwarded-For'] = ", ".join(ips)

def reconstruct_url(environ):
    host = environ.get('HTTP_HOST', '')
    scriptname = environ.get('SCRIPT_NAME', '')
    pathinfo = environ.get('PATH_INFO', '')
    if pathinfo.startswith("http://"):
        url = pathinfo
    elif host:    
        url = 'http://' + host
        url += scriptname
        url += pathinfo
    else:
        url = "http://" + pathinfo
        
    if environ.get('QUERY_STRING', ''):
        url += '?' + environ['QUERY_STRING']
    return url

def get_destination(environ):
    http_host = environ.get('HTTP_HOST', '').lower()
    http_host_split = http_host.split(":")
    path_info = environ.get('PATH_INFO', '').lower()
    if path_info.startswith("http"):
        path_info = urlparse.urlparse(path_info).netloc
    path_info_split = path_info.split(":")
    
    if len(http_host_split) == 2:
        return http_host_split[0], int(http_host_split[1])
    if len(path_info_split) == 2:
        return path_info_split[0], int(path_info_split[1])
    
    # no explicit port, if CONNECT cmd, then prefer 443, else 80 
    if environ["REQUEST_METHOD"] == "CONNECT":
        port = 443
    else:
        port = 80
    if http_host:
        host = http_host
    else:
        host = path_info
    return host, port

BLACKLIST_HEADERS = (
    'HTTP_PROXY_CONNECTION',
)

def copy_request(environ):
    method = environ["REQUEST_METHOD"]
    url = reconstruct_url(environ)

    headers = []
    content_length = environ.get("CONTENT_LENGTH")
    if content_length:
        body = LimitedReader(environ["wsgi.input"], int(content_length))
        headers.append(("Content-Length", content_length))
    else:
        body = ""
        
    for (name, value) in environ.iteritems():
        if name in BLACKLIST_HEADERS:
            continue
        
        if name.startswith("HTTP_") and value is not None:
            headers.append((name[5:].replace("_", "-").lower(), value))
    headers.append(("Connection", "Keep-Alive"))
    headers = dict(headers)
    return method, url, body, headers

class ProxyApplication(object): 
    def __init__(self, timeout=60):
        self.timeout = timeout
    
    def http(self, environ, start_response):
        try:
            host, port = get_destination(environ)
            log.info("HTTP request to (%s:%d)" % (host, port))
            method, url, body, headers = copy_request(environ)
        except Exception, e:
            log.error("[Exception][http]: %s" % str(e))
            start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8")])
            yield "Bad Request"
            return
        
        try:
            set_forwarded_for(environ, headers)
            http_conn = socket.create_connection((host, port), timeout=self.timeout)
            conn = HTTPConnection(host, port=port)
            conn.sock = http_conn
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
        
    def tunnel(self, environ, start_response):
        try:
            host, port = get_destination(environ)
            log.info("CONNECT request to (%s:%d)" % (host, port))
        except Exception, e:
            log.error("[Exception][tunnel]: %s" % str(e))
            start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8")])
            return ["Bad Request"]
        
        try:
            tunnel_conn = socket.create_connection((host, port), timeout=self.timeout)
            environ['TUNNEL_CONN'] = tunnel_conn
            start_response("200 Connection established", [])
            return []
        except socket.timeout:  # @UndefinedVariable
            log.error("Connection Timeout")
            start_response("504 Gateway Timeout", [("Content-Type", "text/plain; charset=utf-8")])
            return ["Gateway Timeout"]
        except Exception, e:
            log.error("[Exception][https]: %s" % str(e))
            start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
            return ["Internal Server Error"]

    def application(self, environ, start_response):
        if environ["REQUEST_METHOD"] == "CONNECT":
            return self.tunnel(environ, start_response)
        else:
            return self.http(environ, start_response)
        
class HTTPProxyServer(object):
    def __init__(self, ip, port, app, log='default'):
        self.ip = ip
        self.port = port
        self.app = app
        self.server = WSGIServer((self.ip, self.port), log=log,
            application=self.app.application, spawn=Pool(500), handler_class=ProxyHandler)
        
    def start(self):
        self.server.start()
        
    def run(self):
        self.server.serve_forever()
    
    def stop(self):
        self.server.stop()
        
    @property
    def closed(self):
        return self.server.closed
        
if __name__ == '__main__':
    logging.basicConfig(
        format='[%(asctime)s][%(name)s][%(levelname)s] - %(message)s',
        datefmt='%Y-%d-%m %H:%M:%S',
        level=logging.DEBUG, 
    )
    HTTPProxyServer("127.0.0.1", 8000, ProxyApplication()).run()

