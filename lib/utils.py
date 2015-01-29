import logging
import sys
import socket
import codecs
import json
import hashlib
import shutil
import urlparse
import urllib

from httplib2 import HTTPConnectionWithTimeout, HTTPSConnectionWithTimeout
    
def idle_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port

class LoggerWriter:
    def __init__(self, logger, level):
        self.logger = logger
        self.level = level

    def write(self, message):
        if message != '\n':
            self.logger.log(self.level, message)
            
def init_logging():
    if len(sys.argv)>1 and sys.argv[1] == "--debug":
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        ch = logging.FileHandler("firefly.log")
        ch.setFormatter(logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s] - %(message)s'))
        logger.addHandler(ch)
        sys.stdout = LoggerWriter(logger, logging.DEBUG)
        sys.stderr = LoggerWriter(logger, logging.DEBUG)
        
def load_file(filename, idna=True):
    f = codecs.open(filename, "r", "utf-8")
    data = [s.strip() for s in f.readlines()]
    f.close()
    data = [s for s in data if s and not s.startswith('#')]
    if not idna:
        return data
    
    ret = []    
    for s in data:
        try:
            parts = s.split(" ")
            ret.append(" ".join([x.encode('idna') for x in parts]))
        except UnicodeError:
            pass
    return ret

def parse_url(url):
    u = urlparse.urlsplit(url)
    scheme = u.scheme
    host = u.netloc
    port = None
    if ":" in u.netloc:
        s = u.netloc.split(":")
        host = s[0]
        port = int(s[1])
    
    path = urlparse.urlunsplit(("", "", u.path, u.query, ""))
    return str(scheme), str(urllib.quote(host)), port, str(urllib.quote(path))

def remote_fetch_with_proxy(url, proxy_info):        
    scheme, host, port, path = parse_url(url)
    if scheme == "http":
        f = HTTPConnectionWithTimeout
    else:
        f = HTTPSConnectionWithTimeout
        
    conn = f(host, port=port, timeout=5, proxy_info=proxy_info)
    conn.request("GET", path)
    resp = conn.getresponse()
    data = resp.read()
    resp.close()
    return data

def remote_update_datafile(proxy, meta, metafile, metaurl, datafile, dataurl):
    updated = False
    r1 = remote_fetch_with_proxy(metaurl, proxy)
    new_meta = json.loads(r1)
    if new_meta['date'] != meta['date']:
        r2 = remote_fetch_with_proxy(dataurl, proxy)
        hasher = hashlib.sha1()
        hasher.update(r2)
        if hasher.hexdigest() == new_meta['sha1']:
            with codecs.open(metafile, "w", "utf-8") as f1:
                f1.write(r1.decode("utf-8"))
            with codecs.open(datafile, "w", "utf-8") as f2:
                f2.write(r2.decode("utf-8"))
            updated = True
    return updated
    
def local_update_datafile(data, datafile):
    filename = datafile + ".tmp"
    f = codecs.open(filename, "w", "utf-8")
    f.write(data)
    f.close()
    shutil.move(filename, datafile)

    
        
    