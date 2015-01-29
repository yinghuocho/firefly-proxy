import os
import codecs
import json
import collections
from collections import defaultdict

from gevent import socket
from fnmatch import fnmatch
if os.name == 'nt':
    import win_inet_pton
    socket.inet_pton = win_inet_pton.inet_pton
    socket.inet_ntop = win_inet_pton.inet_ntop

from gsocks.smart_relay import ForwardDestination
from lib.utils import load_file, remote_update_datafile

def create_connection_hosts(addrs, port, timeout):
    for addr in addrs:
        try:
            return socket.create_connection((addr, port), timeout=timeout)
        except:
            pass
    raise socket.error("all addrs are failed.")  # @UndefinedVariable

def create_hosts(rootdir, confdata):
    f = codecs.open(os.path.join(rootdir, confdata['hosts']['meta']), "r", "utf-8")
    meta = json.loads(f.read(), object_pairs_hook=collections.OrderedDict)
    f.close()
    disabled = load_file(os.path.join(rootdir, confdata['hosts']['disabled']))
    data = load_file(os.path.join(rootdir, confdata['hosts']['data']))
    return FireflyHosts(data, meta, disabled)

def detect_ipv6():
    try:
        addrinfo = socket.getaddrinfo("www.google.com", 80)
        af, _, _, _, _ = addrinfo[0]
        return af == socket.AF_INET6  # @UndefinedVariable
    except:
        return False
    
def hosts_info(rootdir, confdata, hosts):
    return (
        os.path.join(rootdir, confdata['hosts']['data']),
        hosts.count(),
        hosts.groups(),
        hosts.meta['date'],
    )
    
def remote_update_hosts(proxies, rootdir, confdata):
    metafile = os.path.join(rootdir, confdata['hosts']['meta'])
    metaurl = confdata['hosts']['meta_url']
    datafile = os.path.join(rootdir, confdata['hosts']['data'])
    dataurl = confdata['hosts']['data_url']
    
    f = codecs.open(metafile, "r", "utf-8")
    meta = json.loads(f.read(), object_pairs_hook=collections.OrderedDict)
    f.close()
    return remote_update_datafile(proxies, meta, metafile, metaurl, datafile, dataurl)

class FireflyHosts(object):
    def __init__(self, data, meta, disabled):
        self.data = defaultdict(list)
        self.meta = meta
        self.disabled = set(disabled)
        self.has_ipv6 = None
        for entry in data:
            try:
                parts = entry.split()
                parts = [s.strip() for s in parts]
                parts = [s for s in parts if not s.startswith("#")]
                addr, name = parts
                if "." in addr:
                    socket.inet_pton(socket.AF_INET, addr)  # @UndefinedVariable
                elif socket.has_ipv6:                       # @UndefinedVariable
                    socket.inet_pton(socket.AF_INET6, addr) # @UndefinedVariable
                self.data[name.encode("idna")].append(addr)
            except Exception, e:
                print "[Hosts]: ", entry, str(e)
            
    def count(self):
        return len(self.data.keys())
            
    def disable(self, groupname):
        self.disabled.add(groupname)
        
    def match_domain(self, domain, host):
        if fnmatch(domain, host):
            return True
        parts = host.split(".")
        for i in range(len(parts)-1, -1, -1):
            if ".".join(parts[i:]) == domain:
                return True
        return False
        
    def need_redirect(self, method, host):
        if method != "GET":
            return False
        
        groups = self.meta.get('groups', {})
        for (_, domains) in groups.iteritems():
            for (domain, redirect) in domains:
                if self.match_domain(domain, host) and redirect:
                    return True        
        return False
            
    def is_disabled(self, host):
        groups = self.meta.get('groups', {})
        for groupname in self.disabled:
            domains = groups.get(groupname, [])
            for (domain, _) in domains:
                if self.match_domain(domain, host):
                    return True
        return False
    
    def __classify(self, addrs):
        v4 = []
        v6 = []
        for addr in addrs:
            if ":" in addr:
                v6.append(addr)
            else:
                v4.append(addr)
                
        if self.has_ipv6:
            # assume ipv4 is always available.
            return v6 + v4
        else:
            return v4 
            
    def find(self, host):
        if self.has_ipv6 == None:
            self.has_ipv6 = detect_ipv6()
        
        for name, addrs in self.data.iteritems():
            if name == host and not self.is_disabled(host):
                addrs = self.__classify(addrs)
                if addrs:
                    return ForwardDestination("hosts", addrs)
                else:
                    return None
        return None
    
    def groups(self):
        ret = []
        names = self.meta.get('groups', {}).keys()
        for name in names:
            if name in self.disabled:
                ret.append((name, False))
            else:
                ret.append((name, True))
        return ret 
    