import os
import sys
import subprocess
import signal

from gevent.pool import Pool
from geventhttpclient import HTTPClient
from geventhttpclient.url import URL

from shadowsocks import encrypt, asyncdns, eventloop, tcprelay, udprelay

from gsocks.meek_relay import Relay, MeekRelayFactory
from gsocks.server import SocksServer
from lib.ipc import ActorObject, ActorProcess
from lib.utils import init_logging, load_file, remote_fetch_with_proxy, local_update_datafile, get_ca_certs_env

class ShadowSocksChannel(ActorProcess):
    def __init__(self, coordinator):
        super(ShadowSocksChannel, self).__init__()
        self.coordinator = coordinator
        
        confdata = self.coordinator.get('confdata')
        self.ip = confdata['circumvention_proxy_ip']
        self.port = confdata['circumvention_proxy_port']
        self.shadowsocksconf = confdata['circumvention_chan_shadowsocks']
        
    def run(self):
        init_logging()
        key = self.shadowsocksconf['password']
        method = self.shadowsocksconf['method']
        
        config = {
            'local_address': self.ip,
            'local_port': self.port,
            'server': self.shadowsocksconf['server_name'],
            'server_port': self.shadowsocksconf['server_port'],
            'timeout': self.shadowsocksconf['timeout'],
            'fast_open': self.shadowsocksconf['fast_open'],
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
        return "socks5://%s:%d" % (self.ip, self.port) 
    
def remote_update_meek_relays(proxy_info, rootdir, confdata):
    data = remote_fetch_with_proxy(confdata['circumvention_chan_meek']['url'], proxy_info)
    data = data.split("\n")
    data = [s.decode("utf-8") for s in data if s]
    filepath = os.path.join(rootdir, confdata['circumvention_chan_meek']['relays'])
    local = load_file(filepath, idna=False)
    if data == local or not data:
        return False
    else:
        local_update_datafile(u"\n".join(data), filepath)
        return True

class MeekChannel(ActorProcess):
    timeout = 60
    
    def __init__(self, coordinator):
        super(MeekChannel, self).__init__()
        self.coordinator = coordinator
        
        confdata = self.coordinator.get('confdata')
        self.rootdir = self.coordinator.get('rootdir')
        self.ip = confdata['circumvention_proxy_ip']
        self.port = confdata['circumvention_proxy_port']
        self.meekconf = confdata['circumvention_chan_meek']
        self.ready = False
        
    def _test_relay(self, relay, result):
        insecure = "verify" not in relay.properties
        headers = {"Host": relay.hostname}
        url = URL(relay.fronturl)
        client = HTTPClient.from_url(
            url, 
            headers=headers, 
            insecure=insecure, 
            connection_timeout=10,
            network_timeout=10,
            ssl_options={'ca_certs': get_ca_certs_env()}
        )
        for _ in range(2):
            try:
                resp = client.get(url.request_uri)
                succ = (resp.status_code == 200)  # @UndefinedVariable
                resp.release()
                if succ:
                    result.append(relay)
                    return
            except Exception, e:
                print str(e)
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
        p.join()
        return valid_relays
        
    def run(self):
        init_logging()
        relays = load_file(os.path.join(self.rootdir, self.meekconf['relays']), idna=False)
        self.meekfactory = MeekRelayFactory(self._valid_relays(relays), get_ca_certs_env(), self.timeout)
        self.proxy = SocksServer(self.ip, self.port, self.meekfactory)
        self.ready = True
        self.proxy.run()
        
    def IPC_url(self):
        return "socks5://%s:%d" % (self.ip, self.port)
    
    def IPC_update_relays(self):
        relays = load_file(os.path.join(self.rootdir, self.meekconf['relays']), idna=False)
        valid_relays = self._valid_relays(relays)
        if valid_relays:
            print valid_relays
            self.meekfactory.set_relays(valid_relays)
            return True
        return False
        
class SSHChannel(ActorObject):
    def __init__(self, coordinator):
        super(SSHChannel, self).__init__()
        self.coordinator = coordinator
        confdata = self.coordinator.get('confdata')
        self.ip = confdata['circumvention_proxy_ip']
        self.port = confdata['circumvention_proxy_port']
        self.sshconf = confdata['circumvention_chan_ssh']
        
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
        return [s.encode(sys.getfilesystemencoding()) for s in part1 + part2 + part3]
        
    def start(self):        
        rootdir = self.coordinator.get('rootdir')
        args = {}
        kwargs = {}
        if subprocess.mswindows: 
            executable = os.path.join(rootdir, "tools/putty.exe")
            args = self._putty_args(executable, self.ip, self.port, self.sshconf)
            su = subprocess.STARTUPINFO() 
            su.dwFlags |= subprocess.STARTF_USESHOWWINDOW 
            su.wShowWindow = subprocess.SW_HIDE 
            kwargs['startupinfo'] = su 
        self.process = subprocess.Popen(args, **kwargs)
        self.start_actor() 
        
    def join(self):
        if self.process:
            self.process.wait()
            
    def terminate(self):
        self.quit_actor()
        if self.process:
            self.process.terminate()
    
    def is_alive(self):
        if self.process:
            return self.process.poll() is None
        else:
            return False
        
    def IPC_url(self):
        return "socks5://%s:%d" % (self.ip, self.port)
    
class CircumventionChannel(ActorObject):
    supported = {
        'ssh': SSHChannel,
        'meek': MeekChannel,
        'shadowsocks': ShadowSocksChannel,
    }

    def __init__(self, coordinator):
        super(CircumventionChannel, self).__init__()
        self.coordinator = coordinator
        confdata = self.coordinator.get('confdata')
        self.type = confdata['circumvention_chan_type']
        self.channel = self.supported[self.type](coordinator)
        
    def start(self):
        self.channel.start()
        self.start_actor()
    
    def terminate(self):
        self.quit_actor()
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
    
    def IPC_update_meek_relays(self, relays):
        if self.type != "meek":
            return False
        return self.channel.ref().IPC_update_relays(relays)
        