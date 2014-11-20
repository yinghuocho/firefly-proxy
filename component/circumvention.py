import os
import sys
import subprocess
import signal

from gevent.pool import Pool
import requests
import grequests
from shadowsocks import encrypt, asyncdns, eventloop, tcprelay, udprelay

from gsocks.meek_relay import Relay, MeekRelayFactory
from gsocks.server import SocksServer
from lib.ipc import IPC_Host, IPC_Process

class ShadowSocksChannel(IPC_Process):
    def __init__(self, hub_ref):
        super(ShadowSocksChannel, self).__init__()
        self.hub_ref = hub_ref
        self.process = None
        
    def run(self):
        confdata = self.hub_ref.get('confdata')
        proxy_ip = confdata['circumvention_proxy_ip']
        proxy_port = confdata['circumvention_proxy_port']
        shadowsocksconf = confdata['circumvention_chan_shadowsocks']
        
        key = shadowsocksconf['password']
        method = shadowsocksconf['method']
        
        config = {
            'local_address': proxy_ip,
            'local_port': proxy_port,
            'server': shadowsocksconf['server_name'],
            'server_port': shadowsocksconf['server_port'],
            'timeout': shadowsocksconf['timeout'],
            'fast_open': shadowsocksconf['fast_open'],
            'password': key,
            'method': method,
        }
        encrypt.init_table(key, method)
        dns_resolver = asyncdns.DNSResolver()
        tcp_server = tcprelay.TCPRelay(config, dns_resolver, True)
        udp_server = udprelay.UDPRelay(config, dns_resolver, True)
        loop = eventloop.EventLoop()
        dns_resolver.add_to_loop(loop)
        tcp_server.add_to_loop(loop)
        udp_server.add_to_loop(loop)
        
        def handler(signum, _):
            tcp_server.close(next_tick=True)
            udp_server.close(next_tick=True)
        signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM), handler)
        loop.run()
        
    def IPC_url(self):
        confdata = self.hub_ref.get('confdata')
        proxy_ip = confdata['circumvention_proxy_ip']
        proxy_port = confdata['circumvention_proxy_port']
        return "socks5://%s:%d" % (proxy_ip, proxy_port)
        

class MeekChannel(IPC_Process):
    timeout = 60
    
    def __init__(self, hub_ref):
        super(MeekChannel, self).__init__()
        self.hub_ref = hub_ref
        self.process = None
        
    def _test_relay(self, relay, result):
        # We don't want go to system proxies.
        s = requests.Session()
        s.trust_env = False
        verify = "verify" in relay.properties
        stream = "stream" in relay.properties
        headers = {"Host": relay.hostname}
        for _ in range(2):
            try:
                reqs = [grequests.get(relay.fronturl, headers=headers,
                    verify=verify, stream=stream, timeout=5, session=s)]
                resp = grequests.map(reqs, stream=stream)[0]
                if resp.status_code == requests.codes.ok:  # @UndefinedVariable
                    result.append(relay)
                    return
            except:
                pass
        print "meek relay (%s,%s) is not valid" % (relay.fronturl, relay.hostname)
        
    def _valid_relays(self, relays):
        valid_relays = []
        p = Pool(10)
        for s in relays:
            fields = [i.strip() for i in s.split(",")]
            if len(fields) < 3:
                continue
            value = dict(zip(
                ("fronturl", "hostname", "properties", "failure"),
                (fields[0], fields[1], fields[2:], 0)
            ))
            p.spawn(self._test_relay, Relay(**value), valid_relays)
            valid_relays.append(Relay(**value))
        p.join()
        return valid_relays
        
    def run(self):
        confdata = self.hub_ref.get('confdata')
        proxy_ip = confdata['circumvention_proxy_ip']
        proxy_port = confdata['circumvention_proxy_port']
        meekconf = confdata['circumvention_chan_meek']
        
        self.meekfactory = MeekRelayFactory(
            self._valid_relays(meekconf['relays']), self.timeout)
        self.proxy = SocksServer(proxy_ip, proxy_port, self.meekfactory)
        self.proxy.run()
        
    def IPC_url(self):
        confdata = self.hub_ref.get('confdata')
        proxy_ip = confdata['circumvention_proxy_ip']
        proxy_port = confdata['circumvention_proxy_port']
        return "socks5://%s:%d" % (proxy_ip, proxy_port)
        
class SSHChannel(IPC_Host):
    def __init__(self, hub_ref):
        super(SSHChannel, self).__init__()
        self.hub_ref = hub_ref
        self.process = None
        
    def _putty_args(self, executable, proxy_ip, proxy_port, sshconf):
        part1 = [
            executable,
            "-ssh",
            "-N",
            "-C",
            "-P",
            str(sshconf['server_port']),
            "-D",
            "%s:%d" % (proxy_ip, proxy_port)
        ]
        
        if sshconf['auth'] == "key":
            part2 = ["-i", sshconf['keyfile']]
        else:
            part2 = ["-pw", sshconf['password']]
            
        part3 = ["%s@%s" % (sshconf['username'], sshconf['server_name'])]
        return [s.encode(sys.getfilesystemencoding()) for s in part1+part2+part3]
        
    def start(self):
        rootdir = self.hub_ref.get('rootdir')
        confdata = self.hub_ref.get('confdata')
        proxy_ip = confdata['circumvention_proxy_ip']
        proxy_port = confdata['circumvention_proxy_port']
        sshconf = confdata['circumvention_chan_ssh']
        
        args = {}
        kwargs = {}
        if subprocess.mswindows: 
            executable = os.path.join(rootdir, "tools/putty.exe")
            args = self._putty_args(executable, proxy_ip, proxy_port, sshconf)
            su = subprocess.STARTUPINFO() 
            su.dwFlags |= subprocess.STARTF_USESHOWWINDOW 
            su.wShowWindow = subprocess.SW_HIDE 
            kwargs['startupinfo'] = su 
        self.process = subprocess.Popen(args, **kwargs)
        self.start_IPC() 
        
    def join(self):
        if self.process:
            self.process.wait()
            
    def terminate(self):
        self.quit_IPC()
        if self.process:
            self.process.terminate()
    
    def is_alive(self):
        if self.process:
            return self.process.poll() is None
        else:
            return False
        
    def IPC_url(self):
        confdata = self.hub_ref.get('confdata')
        proxy_ip = confdata['circumvention_proxy_ip']
        proxy_port = confdata['circumvention_proxy_port']
        return "socks5://%s:%d" % (proxy_ip, proxy_port)

class CircumventionChannel(IPC_Host):
    supported = {
        'ssh': SSHChannel,
        'meek': MeekChannel,
        'shadowsocks': ShadowSocksChannel,
    }

    def __init__(self, hub_ref):
        super(CircumventionChannel, self).__init__()
        self.hub_ref = hub_ref
        confdata = self.hub_ref.get('confdata')
        self.channel = self.supported[confdata['circumvention_chan_type']](hub_ref)
        
    def start(self):
        self.channel.start()
        self.start_IPC()
    
    def terminate(self):
        self.quit_IPC()
        self.channel.terminate()
    
    def join(self):
        self.channel.join()
    
    def IPC_url(self):
        if self.channel.is_alive():
            return self.channel.ref().IPC_url()
        else:
            return None
    
    def IPC_shadowsocks_methods(self):
        return encrypt.method_supported.keys()
    
    
        