import os
import sys
import json
import codecs
import shutil
import hashlib
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
from lib.utils import open_log
from component.daemon import Daemon
from component.admin import Webadmin
from component.circumvention import CircumventionChannel
from component.local import build_forward_match, HTTPProxy, SocksProxy
from component.brz import Browser

#import logging
#logging.basicConfig(
#    format='[%(asctime)s][%(name)s][%(levelname)s] - %(message)s',
#    datefmt='%Y-%d-%m %H:%M:%S',
#    level=logging.INFO, 
#)

class Hub(IPC_Host):
    def __init__(self, rootdir, conf_file):
        super(Hub, self).__init__()
        
        self.rootdir = rootdir
        self.conf_file = conf_file
        
        self.confdata = None
        self.webadmin = None
        self.daemon = None
        self.cc_channel = None
        self.forward_match = None
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
        
    def load_forward_match(self):
        forward_url = self.IPC_forward_url()
        if forward_url:
            self.forward_match = build_forward_match( 
                os.path.join(self.rootdir, self.confdata['blacklist']),
                os.path.join(self.rootdir, self.confdata['blacklist_meta']),
                os.path.join(self.rootdir, self.confdata['custom_blacklist']),
                os.path.join(self.rootdir, self.confdata['custom_whitelist']),
                forward_url,
            )
        
    def update_forward_match(self):
        self.load_forward_match()
        if self.http_proxy:
            self.http_proxy.ref().IPC_update_forward_match(self.forward_match)
        if self.socks_proxy:
            self.socks_proxy.ref().IPC_update_forward_match(self.forward_match)
            
        
    def run_local_proxy(self):
        self.load_forward_match()
        if self.confdata['enable_http_proxy']:
            try:
                self.http_proxy = HTTPProxy(self.ref(), self.forward_match)
                self.http_proxy.start()
            except Exception, e:
                print "failed to start http proxy: %s" % str(e)
        
        if self.confdata['enable_socks_proxy']:
            try:
                self.socks_proxy = SocksProxy(self.ref(), self.forward_match)
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
             
    def update_blacklist(self):
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
        
        meta_url = self.confdata['blacklist_meta_url']
        meta_file = os.path.join(self.rootdir, self.confdata['blacklist_meta'])
        r1 = requests.get(meta_url, proxies=proxies)
        new_meta = json.loads(r1.text)
        if new_meta['date'] == self.forward_match.blmeta['date']:
            return True
        
        bl_url = self.confdata['blacklist_url']
        bl_file = os.path.join(self.rootdir, self.confdata['blacklist'])
        r2 = requests.get(bl_url, proxies=proxies)
        hasher = hashlib.sha1()
        hasher.update(r2.text.encode("utf-8"))
        if hasher.hexdigest() == new_meta['sha1']:
            with codecs.open(meta_file, "w", "utf-8") as f1:
                f1.write(r1.text)
            with codecs.open(bl_file, "w", "utf-8") as f2:
                f2.write(r2.text)
            return True
        else:
            return False
             
    def misc(self):
        try:
            bl_date = datetime.strptime(self.forward_match.blmeta['date'], '%Y-%m-%d').date()
            if date.today() > bl_date:
                # try to update when old than one day.
                if self.update_blacklist():
                    self.update_forward_match()
        except Exception, e:
            print "failed to execute misc tasks: %s" % str(e)
             
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
                self.update_forward_match()
            return True
        except Exception, e:
            print "failed to update blacklist: %s" % str(e)
            return False
    
    def IPC_blacklist_info(self):
        return (
            os.path.join(self.rootdir, self.confdata['blacklist']),
            len(self.forward_match.bl),
            self.forward_match.blmeta['date']
        )
    
    def IPC_get_custom_blacklist(self):
        return [s.decode("idna") for s in self.forward_match.custom_bl]
    
    def IPC_get_custom_whitelist(self):
        return [s.decode("idna") for s in self.forward_match.custom_wl]
    
    def update_file(self, data, dst):
        filename = dst + ".tmp"
        f = codecs.open(filename, "w", "utf-8")
        f.write(u"\n".join(data))
        f.close()
        shutil.move(filename, dst)
    
    def IPC_update_custom_list(self, custom_bl=None, custom_wl=None):
        if custom_bl:
            self.update_file(custom_bl,
                os.path.join(self.rootdir, self.confdata['custom_blacklist']))
        if custom_wl:
            self.update_file(custom_wl,
                os.path.join(self.rootdir, self.confdata['custom_whitelist']))
        self.update_forward_match()
        
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
    
def close_std():
    sys.stdin.close()
    sys.stdin = open(os.devnull)
    sys.stderr.close
    sys.stderr = open(os.devnull)
        
def main():
    # XXX: this might fix bad file descripter exception caused by freeze_support()
    close_std()
    multiprocessing.freeze_support()
    
    global rootdir
    config = "config.json"
    if len(sys.argv)>1 and sys.argv[1] == "--debug":
        open_log("firefly.log")
    
    os.environ['REQUESTS_CA_BUNDLE'] = \
        os.path.join(rootdir, "ca-bundle.crt").encode(sys.getfilesystemencoding())
    hub = Hub(rootdir, config)
    hub.run()
    
if __name__ == '__main__':
    main()
    