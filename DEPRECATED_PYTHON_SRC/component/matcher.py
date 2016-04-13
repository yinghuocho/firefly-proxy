import os
import json
import fnmatch
import codecs
import collections
from urlparse import urlparse
from gsocks.smart_relay import ForwardMatcher, ForwardDestination

from component.hosts import create_hosts
from lib.utils import load_file, remote_update_datafile

def create_matcher(rootdir, confdata, circumvention_url):
    hosts = create_hosts(rootdir, confdata)
    
    f = codecs.open(os.path.join(rootdir, confdata['blacklist_meta']), "r", "utf-8")
    meta = json.loads(f.read(), object_pairs_hook=collections.OrderedDict)
    f.close()
    blacklist = load_file(os.path.join(rootdir, confdata['blacklist']))
    custom_blacklist = load_file(os.path.join(rootdir, confdata['custom_blacklist']))
    custom_whitelist = load_file(os.path.join(rootdir, confdata['custom_whitelist']))
    
    return FireflyMatcher(
        hosts, 
        BlacklistMatcher(meta, blacklist, custom_blacklist, custom_whitelist, urlparse(circumvention_url))
    )
    
def blacklist_info(rootdir, confdata, blacklist_matcher):
    return (
        os.path.join(rootdir, confdata['blacklist']),
        blacklist_matcher.count(),
        blacklist_matcher.meta['date'],
    )
    
def remote_update_blacklist(proxies, rootdir, confdata):
    metafile = os.path.join(rootdir, confdata['blacklist_meta'])
    metaurl = confdata['blacklist_meta_url']
    datafile = os.path.join(rootdir, confdata['blacklist'])
    dataurl = confdata['blacklist_url']
    
    f = codecs.open(metafile, "r", "utf-8")
    meta = json.loads(f.read(), object_pairs_hook=collections.OrderedDict)
    f.close()
    return remote_update_datafile(proxies, meta, metafile, metaurl, datafile, dataurl)
    

class BlacklistMatcher(ForwardMatcher):
    def __init__(self, meta, blacklist, custom_blacklist, custom_whitelist, url):
        self.meta = meta
        self.blacklist = blacklist
        self.custom_blacklist = custom_blacklist
        self.custom_whitelist = custom_whitelist
        self.dst = ForwardDestination("socks5", url)
            
    def find(self, host, port, proto="tcp"):
        for name in self.custom_whitelist:
            if fnmatch.fnmatch(host, name):
                return None
            
        for name in self.custom_blacklist:
            if fnmatch.fnmatch(host, name):
                return self.dst
            
        parts = host.split(".")
        for i in range(len(parts)-1, -1, -1):
            if ".".join(parts[i:]) in self.blacklist:
                return self.dst
        return None    
    
    def count(self):
        return len(self.blacklist)
    
    def get_custom_blacklist(self):
        # internal data is idna encoded to matching with URLs passed from browser,
        # return UTF-8 to display on config page 
        return [s.decode("idna") for s in self.custom_blacklist]
    
    def get_custom_whitelist(self):
        return [s.decode("idna") for s in self.custom_whitelist]
    
class FireflyMatcher(ForwardMatcher):
    def __init__(self, hosts, blacklist_matcher):
        super(FireflyMatcher, self).__init__()
        self.hosts = hosts
        self.blacklist_matcher = blacklist_matcher
        
    def find(self, host, port, proto="tcp"):
        ret = self.hosts.find(host)
        if ret:
            return ret
        return self.blacklist_matcher.find(host, port, proto)
        
    def need_redirect(self, method, host):
        return self.hosts.need_redirect(method, host)
    
    