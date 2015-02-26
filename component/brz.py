import sys
import os
import threading
import subprocess
import codecs
import urllib
import urlparse
import webbrowser

from lib.ipc import ActorObject

# proxy type
SOCKS5 = 1
HTTP   = 2

def launch_chrome(executable, url, rootdir, proxy_type, proxy_ip, proxy_port, default):
    if proxy_type == SOCKS5:
        proxy_option = '--proxy-server=socks5://%s:%d' % (proxy_ip, proxy_port)
    else:
        proxy_option = '--proxy-server=http://%s:%d' % (proxy_ip, proxy_port)
        
    if not url.startswith("http"):
        # must be local file
        url = urlparse.urljoin('file:', urllib.pathname2url(url.encode(sys.getfilesystemencoding())))
        
    cmdline = [
        executable,
        u'-user-data-dir=%s' % os.path.join(rootdir, "chrome_user_data"),
        proxy_option,
        '--proxy-bypass-list=*.local;<local>',
        '--host-resolver-rules="MAP * 0.0.0.0 , EXCLUDE %s"' % proxy_ip,
        '--new-window',
        url,
    ]
    cmdline = [s.encode(sys.getfilesystemencoding()) for s in cmdline]
    return subprocess.Popen(cmdline)

def launch_chrome_tab(executable, url, rootdir, default):
    if not url.startswith("http"):
        url = urlparse.urljoin('file:', urllib.pathname2url(url.encode(sys.getfilesystemencoding())))
        
    cmdline = [
        executable,
        u'-user-data-dir=%s' % os.path.join(rootdir, "chrome_user_data"),
        '--proxy-bypass-list="*.local;<local>"',
        url,
    ]
    cmdline = [s.encode(sys.getfilesystemencoding()) for s in cmdline]
    return subprocess.Popen(cmdline)

def launch_firefox(executable, url, rootdir, proxy_type, proxy_ip, proxy_port, default):
    profilepath = os.path.join(rootdir, "firefox_user_data")
    if not os.path.isdir(profilepath):
        os.makedirs(profilepath)
    data = [
        'user_pref("network.proxy.type", 1);',
        'user_pref("network.dns.disablePrefetch", true);',
    ]
    if proxy_type == SOCKS5:
        data += [
            'user_pref("network.proxy.socks", "%s");' % proxy_ip,
            'user_pref("network.proxy.socks_port", %d);' % proxy_port,
            'user_pref("network.proxy.socks_remote_dns", true);',
            'user_pref("network.proxy.http", "");',
            'user_pref("network.proxy.http_port", 0);',
            'user_pref("network.proxy.ssl", "");',
            'user_pref("network.proxy.ssl_port", 0);',
            'user_pref("network.proxy.share_proxy_settings", false);',
        ]
    else:
        data += [
            'user_pref("network.proxy.socks", "");',
            'user_pref("network.proxy.socks_port", 0);',
            'user_pref("network.proxy.socks_remote_dns", true);',
            'user_pref("network.proxy.http", "%s");' % proxy_ip,
            'user_pref("network.proxy.http_port", %d);' % proxy_port,
            'user_pref("network.proxy.ssl", "%s");' % proxy_ip,
            'user_pref("network.proxy.ssl_port", %d);' % proxy_port,
            'user_pref("network.proxy.share_proxy_settings", false);',
        ]
    
    f = codecs.open(os.path.join(profilepath, "user.js"), "w", "utf-8")
    f.write("\n".join(data))
    f.write("\n")
    f.close()

    if not url.startswith("http"):
        # must be local file
        url = urlparse.urljoin('file:', urllib.pathname2url(url.encode(sys.getfilesystemencoding())))
        
    cmdline = [
        executable,
        '-profile',
        profilepath,
        '-new-window',
        url,
    ]
    cmdline = [s.encode(sys.getfilesystemencoding()) for s in cmdline]
    return subprocess.Popen(cmdline)

def launch_firefox_tab(executable, url, rootdir, default):
    profilepath = os.path.join(rootdir, "firefox_user_data")
    if not url.startswith("http"):
        # must be local file
        url = urlparse.urljoin('file:', urllib.pathname2url(url.encode(sys.getfilesystemencoding())))
        
    cmdline = [
        executable,
        '-profile',
        profilepath,
        '-remote',
        u'openURL(%s,new-tab)' % url,
    ]
    cmdline = [s.encode(sys.getfilesystemencoding()) for s in cmdline]
    return subprocess.Popen(cmdline)

def iterate_browsers():
    return []

PRIORITY_OF_DEFAULT = 10
implemented = {
    # priority, supported proxy, launch_function
    "chrom"    : (3, (SOCKS5, HTTP), (launch_chrome, launch_chrome_tab)),
    "firefox"  : (2, (SOCKS5, HTTP), (launch_firefox, launch_firefox_tab)),
}

# resume 
resume_proxy_config = None

if os.name == 'nt':
    import _brz_win
    iterate_browsers = _brz_win.iterate_browsers
    implemented['iexplore'] = (1, (HTTP,), (_brz_win.launch_ie, _brz_win.launch_ie_tab))
    resume_function = _brz_win.resume_ie_settings

class Browser(ActorObject):
    def __init__(self, coordinator, http_proxy_enabled, socks_proxy_enabled, initial_url=None):
        super(Browser, self).__init__()
        self.coordinator = coordinator
        self.http_proxy_enabled = http_proxy_enabled
        self.socks_proxy_enabled = socks_proxy_enabled
        self.initial_url = initial_url
        
        self.instance = None
        self.cleaner = None
        
    def _launch_browser(self, url, tab=False):
        addrs = {}
        if self.http_proxy_enabled:
            addrs[HTTP] = self.coordinator.IPC_http_proxy_addr()
        if self.socks_proxy_enabled:
            addrs[SOCKS5] = self.coordinator.IPC_socks_proxy_addr()
        if not addrs:
            webbrowser.open(url)
            return None
        
        browsers = []
        for (name, executable, default, _) in iterate_browsers():
            for k in implemented.keys():
                if k in name.lower():
                    priority, types, (launch_func, launch_tab_func) = implemented[k] 
                    addr = None
                    for t in types:
                        if t in addrs:
                            addr = (t, addrs[t])
                            break
                    if not addr:
                        break            
                    if default:
                        priority = PRIORITY_OF_DEFAULT    
                    browsers.append((priority, addr, (launch_func, launch_tab_func), executable, default))
                    break       
        if not browsers:
            return None
        # sort available browsers by pritority
        browsers.sort(key=lambda x: x[0], reverse=True)
        (_, (proxy_type, (proxy_ip, proxy_port)), (launch_func, launch_tab_func), executable, default) = browsers[0]
        
        rootdir = self.coordinator.get('rootdir')
        if tab:
            return launch_tab_func(executable, url, rootdir, default)
        else:
            return launch_func(executable, url, rootdir, proxy_type, proxy_ip, proxy_port, default)
    
    def default_page(self):
        confdata = self.coordinator.get('confdata')
        rootdir = self.coordinator.get('rootdir')
        defaultpage = confdata['home_page']
        if not defaultpage.startswith("http://"):
            defaultpage = os.path.join(rootdir, defaultpage)
        return defaultpage
    
    def start(self):
        url = self.initial_url
        if not url:
            url = self.default_page() 
        self.instance = self._launch_browser(url)
        self.start_actor()
        # cleaner to quit IPC actor after browser closed, 
        # also try to resume previous browser setting.
        self.cleaner = threading.Thread(target=self.clean)
        self.cleaner.daemon = True
        self.cleaner.start()
        
    def clean(self):
        if self.instance:
            self.instance.wait()
            self.quit_actor()
            if resume_proxy_config:
                resume_proxy_config()
        
    def terminate(self):
        self.quit_actor()
        if self.instance:
            self.instance.terminate()
            
    def is_alive(self):
        if self.instance:
            return self.instance.poll() is None
        else:
            return False
    
    def join(self):
        if self.cleaner:
            self.cleaner.join()
        
    def IPC_open_default_page(self):
        self._launch_browser(self.default_page(), tab=True)
        
    def IPC_open_url(self, url):
        self._launch_browser(url, tab=True)

