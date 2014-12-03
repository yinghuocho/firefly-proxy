import os
import sys
import json
import codecs
import shutil
import hashlib
import collections
import multiprocessing
from datetime import datetime, date
if getattr(sys, 'frozen', False):
    rootdir = os.path.dirname(sys.executable)
else:
    rootdir = os.path.dirname(os.path.realpath(__file__))
# make all filenames based on rootdir being unicode
rootdir = rootdir.decode(sys.getfilesystemencoding())
sys.path.append(rootdir)

import requesocks as requests

from lib.ipc import IPC_Host
from lib.utils import init_logging
from component.daemon import Daemon
from component.admin import Webadmin
from component.circumvention import CircumventionChannel
from component.local import create_forward_matcher, HTTPProxy, SocksProxy
from component.brz import Browser

class Hub(IPC_Host):
    def __init__(self, rootdir, conf_file):
        super(Hub, self).__init__()
        
        self.rootdir = rootdir
        self.conf_file = conf_file
        
        self.confdata = None
        self.webadmin = None
        self.daemon = None
        self.cc_channel = None
        self.forward_matcher = None
        self.http_proxy = None
        self.socks_proxy = None
        self.browser = None
        
    def initialize(self):
        self.loadconf()
        self.ref().share('rootdir', self.rootdir)
        self.ref().share('confdata', self.confdata)
        self.start_IPC()
        
    def loadconf(self):
        f = codecs.open(os.path.join(self.rootdir, self.conf_file), "r", "utf-8")
        self.confdata = json.loads(f.read())
        f.close()
        
    def backup_conf(self):
        conf = os.path.join(self.rootdir, self.conf_file)
        shutil.copy(conf, conf + ".last")
        default = conf + ".default"
        if not os.path.isfile(default):
            shutil.copy(conf, default)
        
    def recover_conf(self):
        conf = os.path.join(self.rootdir, self.conf_file)
        shutil.copy(conf + ".last", conf)
    
    def run_daemon(self):
        self.daemon = Daemon(self.ref())
        self.daemon.start()
        
    def run_webadmin(self):
        self.webadmin = Webadmin(self.ref())
        self.webadmin.start()
            
    def run_cc_channel(self):
        try:
            self.cc_channel = CircumventionChannel(self.ref())
            self.cc_channel.start()
        except Exception, e:
            print "failed to start circumvention channel: %s" % str(e)
        
    def load_forward_matcher(self):
        f = codecs.open(
            os.path.join(self.rootdir, self.confdata['blacklist_meta']), "r", "utf-8")
        self.blacklist_meta = json.loads(f.read())
        f.close()
        f = codecs.open(
            os.path.join(self.rootdir, self.confdata['hosts']['meta']), "r", "utf-8")
        self.hosts_meta = json.loads(f.read(), object_pairs_hook=collections.OrderedDict)
        f.close()
        
        f = codecs.open(
            os.path.join(self.rootdir, self.confdata['hosts']['disabled']), "r", "utf-8")
        self.hosts_disabled_groups = [s.strip() for s in f.readlines() if s and not s.startswith('#')]
        
        forward_url = self.IPC_forward_url()
        if forward_url:
            self.forward_matcher = create_forward_matcher( 
                os.path.join(self.rootdir, self.confdata['blacklist']),
                os.path.join(self.rootdir, self.confdata['custom_blacklist']),
                os.path.join(self.rootdir, self.confdata['custom_whitelist']),
                forward_url,
                
                os.path.join(self.rootdir, self.confdata['hosts']['data']),
                self.hosts_meta.get('groups', {}),
                self.hosts_disabled_groups,
            )
        
    def update_forward_matcher(self):
        self.load_forward_matcher()
        if self.http_proxy:
            self.http_proxy.ref().IPC_update_forward_matcher(self.forward_matcher)
        if self.socks_proxy:
            self.socks_proxy.ref().IPC_update_forward_matcher(self.forward_matcher)
            
    def run_local_proxy(self):
        self.load_forward_matcher()
        if self.confdata['enable_http_proxy']:
            try:
                self.http_proxy = HTTPProxy(self.ref(), self.forward_matcher)
                self.http_proxy.start()
            except Exception, e:
                print "failed to start http proxy: %s" % str(e)
        
        if self.confdata['enable_socks_proxy']:
            try:
                self.socks_proxy = SocksProxy(self.ref(), self.forward_matcher)
                self.socks_proxy.start()
            except Exception, e:
                print "failed to start socks proxy: %s" % str(e)
                
    def run_browser(self, initial_url=None):
        http_proxy_enabled = False
        socks_proxy_enabled = False
        if self.http_proxy:
            http_proxy_enabled = True
        if self.socks_proxy:
            socks_proxy_enabled = True
            
        if not http_proxy_enabled and not socks_proxy_enabled:
            return
        
        try:
            self.browser = Browser(self.ref(), http_proxy_enabled, socks_proxy_enabled, initial_url=initial_url)
            self.browser.start()
        except Exception, e:
            print "failed to launch browser failed: %s" % str(e)
                 
    def update_data(self, meta, metafile, metaurl, datafile, dataurl):
        if self.socks_proxy:
            url = self.socks_proxy.ref().IPC_url()
        elif self.http_proxy:
            url = self.http_proxy.ref().IPC_url()
        else:
            url = ""
        if url:
            proxies = {
                'http': url,
                'https': url,
            }
        else:
            # use system proxies
            proxies = {}
        
        r1 = requests.get(metaurl, proxies=proxies)
        new_meta = json.loads(r1.text)
        if new_meta['date'] == meta['date']:
            return True
        
        r2 = requests.get(dataurl, proxies=proxies)
        hasher = hashlib.sha1()
        hasher.update(r2.text.encode("utf-8"))
        if hasher.hexdigest() == new_meta['sha1']:
            with codecs.open(metafile, "w", "utf-8") as f1:
                f1.write(r1.text)
            with codecs.open(datafile, "w", "utf-8") as f2:
                f2.write(r2.text)
            return True
        else:
            return False
             
    def update_blacklist(self):
        return self.update_data(
            self.blacklist_meta,
            os.path.join(self.rootdir, self.confdata['blacklist_meta']),
            self.confdata['blacklist_meta_url'],
            os.path.join(self.rootdir, self.confdata['blacklist']),
            self.confdata['blacklist_url'],
        )
        
    def update_hosts(self):
        return self.update_data(
            self.hosts_meta,
            os.path.join(self.rootdir, self.confdata['hosts']['meta']),
            self.confdata['hosts']['meta_url'],
            os.path.join(self.rootdir, self.confdata['hosts']['data']),
            self.confdata['hosts']['data_url'],
        )
             
    def misc(self):
        try:
            bl_date = datetime.strptime(self.blacklist_meta['date'], '%Y-%m-%d').date()
            if date.today() > bl_date:
                # try to update when old than one day.
                if self.update_blacklist():
                    self.update_forward_matcher()
        except Exception, e:
            print "failed to update blacklist: %s" % str(e)
            
        try:
            hosts_date = datetime.strptime(self.hosts_meta['date'], '%Y-%m-%d').date()
            if date.today() > hosts_date:
                if self.update_hosts():
                    self.update_forward_matcher()
        except Exception, e:
            print "failed to udpate hosts: %s" % str(e)
             
    def run(self):
        try:
            self.initialize()
            self.run_webadmin()
            self.run_daemon()
        except Exception, e:
            print "failed to start basic steps/processes: %s, try to recover ..." % str(e)
            if self.recover_conf():
                if self.webadmin:
                    self.webadmin.terminate()
                    self.webadmin.join()
                if self.daemon:
                    self.daemon.terminate()
                    self.daemon.join()
                self.initialize()
                self.run_webadmin()
                self.run_daemon()
                
        self.backup_conf()
        self.run_cc_channel()
        self.run_local_proxy()
        if self.confdata['launch_browser']:
            self.run_browser()
            
        # misc tasks after launching 
        self.misc()
        # wait for daemon to quit, then clean
        self.daemon.join()
        self.end()
        
    def end(self):
        self.webadmin.terminate()
        self.webadmin.join()
        self.cc_channel.terminate()
        self.cc_channel.join()
        if self.http_proxy:
            self.http_proxy.terminate()
            self.http_proxy.join()
        if self.socks_proxy:
            self.socks_proxy.terminate()
            self.socks_proxy.join()
        if self.browser:
            self.browser.terminate()
            self.browser.join()
            
    def write_file(self, data, dst):
        filename = dst + ".tmp"
        f = codecs.open(filename, "w", "utf-8")
        f.write(u"\n".join(data))
        f.close()
        shutil.move(filename, dst)
    
    def IPC_update_config(self, data):
        try:
            self.confdata.update(data)
            f = codecs.open(os.path.join(self.rootdir, self.conf_file), "w", "utf-8")
            f.write(json.dumps(self.confdata,
                        sort_keys=True,
                        indent=4,
                        separators=(',', ': '),
                        ensure_ascii=False))
            f.close()
            return data
        except Exception, e:
            print "failed to update config: %s" % str(e)
            return None
        
    def IPC_forward_url(self):
        return self.cc_channel.ref().IPC_url()
    
    def IPC_update_blacklist(self):
        try:
            if self.update_blacklist():
                self.update_forward_matcher()
            return True
        except Exception, e:
            print "failed to update blacklist: %s" % str(e)
            return False
        
    def IPC_update_hosts(self):
        try:
            if self.update_hosts():
                self.update_forward_matcher()
            return True
        except Exception, e:
            print "failed to update hosts file: %s" % str(e)
            return False   
    
    def IPC_blacklist_info(self):
        return (
            os.path.join(self.rootdir, self.confdata['blacklist']),
            len(self.forward_matcher.bl),
            self.blacklist_meta['date']
        )
    
    def IPC_hosts_info(self):
        return (
            os.path.join(self.rootdir, self.confdata['hosts']['data']),
            self.forward_matcher.hosts.domain_count(),
            self.hosts_meta['date']
        )
    
    def IPC_get_custom_blacklist(self):
        return [s.decode("idna") for s in self.forward_matcher.custom_bl]
    
    def IPC_get_custom_whitelist(self):
        return [s.decode("idna") for s in self.forward_matcher.custom_wl]
    
    def IPC_update_custom_list(self, custom_bl=None, custom_wl=None):
        if custom_bl:
            self.write_file(custom_bl,
                os.path.join(self.rootdir, self.confdata['custom_blacklist']))
        if custom_wl:
            self.write_file(custom_wl,
                os.path.join(self.rootdir, self.confdata['custom_whitelist']))
        self.update_forward_matcher()
        
    def IPC_socks_proxy_addr(self):
        return self.socks_proxy.ref().IPC_addr()
    
    def IPC_http_proxy_addr(self):
        return self.http_proxy.ref().IPC_addr()
    
    def IPC_shadowsocks_methods(self):
        return self.cc_channel.ref().IPC_shadowsocks_methods()
    
    def IPC_launch_browser(self):
        if self.browser and self.browser.is_alive():
            return self.browser.ref().IPC_open_default_page()
        else:
            self.run_browser()
            
    def IPC_open_admin_url(self):
        url =  self.webadmin.ref().IPC_url()
        if self.browser and self.browser.is_alive():
            return self.browser.ref().IPC_open_url(url)
        else:
            self.run_browser(url)
            
    def IPC_resume_default_config(self):
        conf = os.path.join(self.rootdir, self.conf_file)
        shutil.copy(conf + ".default", conf)
        self.loadconf()
        return self.confdata
    
    def IPC_hosts_groups(self):
        ret = []
        groups = self.hosts_meta.get('groups', {}).keys()
        for name in groups:
            if name in self.hosts_disabled_groups:
                enabled = False
            else:
                enabled = True
            ret.append((name, enabled))
        return ret
    
    def IPC_update_hosts_disabled(self, disabled):
        self.write_file(disabled,
                os.path.join(self.rootdir, self.confdata['hosts']['disabled']))
        self.update_forward_matcher()
    
def close_std():
    sys.stdin.close()
    sys.stdin = open(os.devnull)
    sys.stderr.close
    sys.stderr = open(os.devnull)
        
def main():
    # XXX: this might fix bad file descripter exception caused by freeze_support()
    close_std()
    multiprocessing.freeze_support()
    init_logging() 
    
    global rootdir
    config = "config.json"
    os.environ['REQUESTS_CA_BUNDLE'] = \
        os.path.join(rootdir, "ca-bundle.crt").encode(sys.getfilesystemencoding())
    hub = Hub(rootdir, config)
    hub.run()
    
if __name__ == '__main__':
    main()
    