# socks5 frontend
import logging
import sys

from gevent import socket
from gevent.server import StreamServer
from gevent.pool import Pool

log = logging.getLogger(__name__)

class SocksServer(object):
    def __init__(self, ip, port, relayfactory, timeout=30, maxclient=200):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.relayfactory = relayfactory
        self.pool = Pool(maxclient)
        addrinfo = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM, socket.SOL_TCP)
        af, socktype, proto, _, localaddr = addrinfo[0]
        self.server = StreamServer(localaddr, self._handle, spawn=self.pool)
        
    def _handle(self, sock, addr):
        try:
            sock.settimeout(self.timeout)
            session = self.relayfactory.create_relay_session(sock, addr)
            session.process()
        except Exception, e:
            log.error("[Exception][SocksServer]: %s" % str(e))
            
    def stop(self):
        return self.server.stop()
        
    @property
    def closed(self):
        return self.server.closed
            
    def start(self):
        self.server.start()
        
    def run(self):
        self.server.serve_forever()
    
    
        