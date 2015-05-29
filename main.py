import os
import sys
import json
import codecs
import shutil
import time
from datetime import datetime, date
import multiprocessing
import threading

if getattr(sys, 'frozen', False):
    rootdir = os.path.dirname(sys.executable)
else:
    rootdir = os.path.dirname(os.path.realpath(__file__))
# make all filenames based on rootdir being unicode
rootdir = rootdir.decode(sys.getfilesystemencoding())
sys.path.append(rootdir)

from lib.utils import init_logging, local_update_datafile, set_ca_certs_env, singleton_check, singleton_clean
from lib.ipc import ActorObject
from component.ui import UI
from component.admin import Admin
from component.circumvention import CircumventionChannel, remote_update_meek_relays
from component.local import HTTPProxy, SocksProxy
from component.brz import Browser
from component.matcher import create_matcher, blacklist_info, remote_update_blacklist
from component.hosts import hosts_info, remote_update_hosts
    
class Coordinator(ActorObject):
    def __init__(self, rootdir, conf_file):
        super(Coordinator, self).__init__()
        
        self.rootdir = rootdir
        self.conf_file = conf_file
        
        self.confdata = None
        self.admin = None
        self.ui = None
        self.cc_channel = None
        
        self.matcher = None
        self.http_proxy = None
        self.socks_proxy = None
        self.browser = None
    
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
        try:
            conf = os.path.join(self.rootdir, self.conf_file)
            shutil.copy(conf + ".last", conf)
            return True
        except:
            return False
        
    def initialize(self):
        self.singleton = singleton_check(self.rootdir)
        if not self.singleton:
            sys.exit(-1)
        
        self.loadconf()
        self.ref().share('rootdir', self.rootdir)
        self.ref().share('confdata', self.confdata)
        self.start_actor()
        
    def start_ui(self):
        self.ui = UI(self.ref())
        self.ui.start()
        
    def start_admin(self):
        self.admin = Admin(self.ref())
        self.admin.start()
        
    def start_cc_channel(self):
        try:
            self.cc_channel = CircumventionChannel(self.ref())
            self.cc_channel.start()
        except Exception, e:
            print "failed to start circumvention channel: %s" % str(e)
            
    def start_local_proxy(self):
        global rootdir
        
        circumvention_url = self.IPC_circumvention_url()
        self.matcher = create_matcher(rootdir, self.confdata, circumvention_url)
        if self.confdata['enable_http_proxy']:
            try:
                self.http_proxy = HTTPProxy(self.ref(), self.matcher)
                self.http_proxy.start()
            except Exception, e:
                print "failed to start http proxy: %s" % str(e)
        
        if self.confdata['enable_socks_proxy']:
            try:
                self.socks_proxy = SocksProxy(self.ref(), self.matcher)
                self.socks_proxy.start()
            except Exception, e:
                print "failed to start socks proxy: %s" % str(e)
                
    def proxy_info(self):
        if self.socks_proxy:
            #ip, port = self.socks_proxy.ref().IPC_addr()
            #return ProxyInfo(socks.PROXY_TYPE_SOCKS5, ip, port, True, None, None)
            url = self.socks_proxy.ref().IPC_url()
            return {'http': url, 'https': url}
        elif self.http_proxy:
            #ip, port = self.http_proxy.ref().IPC_addr()
            #return ProxyInfo(socks.PROXY_TYPE_HTTP, ip, port, True, None, None)
            url = self.http_proxy.ref().IPC_url()
            return {'http': url, 'https': url}
        else:
            #return None
            return {}
                
    def update_matcher(self):
        circumvention_url = self.IPC_circumvention_url()
        self.matcher = create_matcher(rootdir, self.confdata, circumvention_url)
        if self.http_proxy:
            self.http_proxy.ref().IPC_update_matcher(self.matcher)
        if self.socks_proxy:
            self.socks_proxy.ref().IPC_update_matcher(self.matcher)
                
    def start_browser(self, url=None):
        http_proxy_enabled = True if self.http_proxy else False
        socks_proxy_enabled = True if self.socks_proxy else False
        #if not http_proxy_enabled and not socks_proxy_enabled:
        #    return
        try:
            self.browser = Browser(self.ref(), http_proxy_enabled, socks_proxy_enabled, initial_url=url)
            self.browser.start()
        except Exception, e:
            print "failed to launch browser failed: %s" % str(e)
            
    def check_and_update_blacklist(self):
        try:
            blacklist_date = datetime.strptime(self.matcher.blacklist_matcher.meta['date'], '%Y-%m-%d').date()
            if date.today() > blacklist_date:
                updated = remote_update_blacklist(self.proxy_info(), self.rootdir, self.confdata)
                if updated:
                    self.update_matcher()
        except Exception, e:
            print "failed to update blacklist: %s" % str(e)
            
    def check_and_update_hosts(self):
        try:
            hosts_date = datetime.strptime(self.matcher.hosts.meta['date'], '%Y-%m-%d').date()
            if date.today() > hosts_date:
                updated = remote_update_hosts(self.proxy_info(), self.rootdir, self.confdata)
                if updated:
                    self.update_matcher()
        except Exception, e:
            print "failed to update hosts: %s" % str(e)
            
    def update_meek_relays(self):
        try:
            updated = remote_update_meek_relays(self.proxy_info(), self.rootdir, self.confdata)
            if updated:
                self.cc_channel.ref().IPC_update_meek_relays()
        except Exception, e:
            print "failed to update meek relays: %s" % str(e)
            
    def check_for_update(self):
        time.sleep(20)
        if self.cc_channel.type == "meek":
            self.update_meek_relays()
        self.check_and_update_blacklist()
        self.check_and_update_hosts()
        
    def run(self):
        try:
            self.initialize()
            self.start_cc_channel()
            self.start_admin()
            self.start_ui()
            self.start_local_proxy()
        except Exception, e:
            print "failed to start basic steps/processes: %s, try to recover ..." % str(e)
            if not self.recover_conf():
                raise e
            
            self.end()
            self.initialize()
            self.start_cc_channel()
            self.start_admin()
            self.start_ui()
            self.start_local_proxy()
            
        self.backup_conf()
        if self.confdata['launch_browser']:
            self.start_browser()
            
        t = threading.Thread(target=self.check_for_update)
        t.daemon = True
        t.start()
        
        self.ui.join()
        self.end()
        
    def end(self):
        if self.admin:
            self.admin.terminate()
            self.admin.join()
        if self.cc_channel:
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
        singleton_clean(self.rootdir, self.singleton)
            
    # IPC interfaces
    def IPC_circumvention_url(self):
        """ask circumvention channel for forwarding url"""
        return self.cc_channel.ref().IPC_url()
    
    def IPC_socks_proxy_addr(self):
        return self.socks_proxy.ref().IPC_addr()
    
    def IPC_http_proxy_addr(self):
        return self.http_proxy.ref().IPC_addr()
    
    def IPC_launch_browser(self):
        if self.browser and self.browser.is_alive():
            return self.browser.ref().IPC_open_default_page()
        else:
            self.start_browser()
            
    def IPC_open_admin_url(self):
        url =  self.admin.ref().IPC_url()
        if self.browser and self.browser.is_alive():
            return self.browser.ref().IPC_open_url(url)
        else:
            self.start_browser(url)
            
    def IPC_shadowsocks_methods(self):
        return self.cc_channel.ref().IPC_shadowsocks_methods()
    
    def IPC_blacklist_info(self):
        return blacklist_info(self.rootdir, self.confdata, self.matcher.blacklist_matcher)
        
    def IPC_hosts_info(self):
        return hosts_info(self.rootdir, self.confdata, self.matcher.hosts)
        
    def IPC_get_custom_blacklist(self):
        return self.matcher.blacklist_matcher.get_custom_blacklist()
    
    def IPC_get_custom_whitelist(self):
        return self.matcher.blacklist_matcher.get_custom_whitelist()
    
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
        
    def IPC_resume_default_config(self):
        conf = os.path.join(self.rootdir, self.conf_file)
        shutil.copy(conf + ".default", conf)
        self.loadconf()
        return self.confdata
    
    def IPC_update_blacklist(self):
        try:
            updated = remote_update_blacklist(self.proxy_info(), self.rootdir, self.confdata)
            if updated:
                self.update_matcher()
            return True
        except Exception, e:
            print "failed to update blacklist: %s" % str(e)
            return False
        
    def IPC_update_custom_list(self, custom_bl=None, custom_wl=None):
        if custom_bl:
            local_update_datafile(u"\n".join(custom_bl),
                os.path.join(self.rootdir, self.confdata['custom_blacklist']))
        if custom_wl:
            local_update_datafile(u"\n".join(custom_wl),
                os.path.join(self.rootdir, self.confdata['custom_whitelist']))
        self.update_matcher()
        
    def IPC_update_hosts(self, remote=True):
        try:
            if remote:
                remote_update_hosts(self.proxy_info(), self.rootdir, self.confdata)
            self.update_matcher()    
            return True
        except Exception, e:
            print "failed to update hosts: %s" % str(e)
            return False 
        
    def IPC_update_hosts_disabled(self, disabled):
        local_update_datafile(u"\n".join(disabled), os.path.join(self.rootdir, self.confdata['hosts']['disabled']))
        self.update_matcher()
        
def close_std():
    sys.stdin.close()
    sys.stdin = open(os.devnull)
    sys.stderr.close
    sys.stderr = open(os.devnull)
        
def main():
    close_std()
    multiprocessing.freeze_support()
    init_logging()
    
    global rootdir
    conf_file = "config.json"
    set_ca_certs_env(os.path.join(rootdir, "cacert.pem").encode(sys.getfilesystemencoding()))
    coordinator = Coordinator(rootdir, conf_file)
    coordinator.run()
    
if __name__ == '__main__':
    main()
