import logging
import sys
import socket
import codecs
import json
import hashlib
import shutil
import urlparse
import urllib
import os

import requests
import requesocks
    
def idle_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port

def set_ca_certs_env(filepath):
    os.environ['CA_BUNDLE'] = filepath
    
def get_ca_certs_env():
    return os.getenv('CA_BUNDLE', "")

class LoggerWriter:
    def __init__(self, logger, level):
        self.logger = logger
        self.level = level

    def write(self, message):
        if message != '\n':
            self.logger.log(self.level, message)
            
    def flush(self):
        pass
            
def init_logging():
    if len(sys.argv)>1 and sys.argv[1] == "--debug":
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        ch = logging.FileHandler("firefly.log")
        ch.setFormatter(logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s] - %(message)s'))
        logger.addHandler(ch)
        sys.stdout = LoggerWriter(logger, logging.DEBUG)
        sys.stderr = LoggerWriter(logger, logging.DEBUG)
    else:
        logger = logging.getLogger()
        logger.setLevel(logging.INFO)
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter('[%(asctime)s][%(name)s][%(levelname)s] - %(message)s'))
        logger.addHandler(ch)
        
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
    if 'socks' in json.dumps(proxy_info):
        s = requesocks.Session()
    else:
        s = requests.Session()
        
    s.trust_env = False
    s.proxies = proxy_info
    retry = 2
    while True:
        try:
            r = s.get(url, verify=get_ca_certs_env())
            if r.status_code != requests.codes.ok:  # @UndefinedVariable
                raise Exception("invalid response")
            return r.text.encode("utf-8")
        except Exception, e:
            if retry > 0:
                print str(e), "give it another chance ..."
                retry -= 1
            else:
                raise

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
    
def singleton_check(rootdir):
    f = None
    lock = os.path.join(rootdir, os.name+"lock")
    if os.name == 'nt':
        try:
            if os.path.exists(lock):
                os.unlink(lock)
            f = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_RDWR)
        except EnvironmentError, e:
            if e.errno != 13:
                print str(e)
            return False
    else:
        try:
            import fcntl
            f = open(lock, 'w')
            fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except EnvironmentError, e:
            if not f is not None:
                print str(e)
            return False
    return f

def singleton_clean(rootdir, f):
    lock = os.path.join(rootdir, os.name+"lock")
    try:
        if os.name == 'nt':
            os.close(f)
            os.unlink(lock)
        else:
            import fcntl
            fcntl.lockf(f, fcntl.LOCK_UN)
            f.close() # ???
            os.unlink(lock)
    except Exception, e:
        print str(e)
        
def which(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, _ = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file
    return None