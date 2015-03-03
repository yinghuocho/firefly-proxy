#!/usr/bin/python
# -*- coding: utf-8 -*-

import json

import web
from web.contrib.template import render_mako

urls = (
    '/static/(.*)', 'static',
    
    '/about', 'about',
    '/proxy', 'proxy',
    '/blacklist', 'blacklist',
    '/hosts', 'hosts',
    
    '/proxy/settings/default', 'default_settings',
    '/proxy/settings/local', 'localproxy_settings',
    '/proxy/settings/browser', 'browser_settings',
    '/proxy/settings/circumvention', 'circumvention_settings',
    
    '/blacklist/bl', 'bl',
    '/blacklist/custom_bl', 'custom_bl',
    '/blacklist/custom_wl', 'custom_wl',
    
    '/hosts/data', 'hosts_data',
    '/hosts/group', 'hosts_group',
)

render = render_mako(
    directories=['templates'],
    input_encoding='utf-8',
    output_encoding='utf-8',
)

need_reboot = False
coordinator = None

def change(orig, update):
    newdata = orig.copy()
    newdata.update(update)
    if newdata == orig:
        return False
    else:
        return True
    
def get_int(data, key, default):
    try:
        return int(data[key])
    except Exception, e:
        print e
        return default
            
def update_config(update, reboot=True, ipc=True, reload_hosts=False):
    global coordinator, need_reboot
    
    try:
        if not change(coordinator.get('confdata'), update):
            web.header('Content-Type', 'application/json')
            resp = {'message': u'配置没有变化'}
            return json.dumps(resp)
        if ipc:
            updated = coordinator.IPC_update_config(update)
        else:
            updated = update
        if reload_hosts:
            coordinator.IPC_update_hosts(remote=False)
            
        # update local confdata so webpage displays updated values
        coordinator.get('confdata').update(updated)
        if reboot:
            need_reboot = True
        web.header('Content-Type', 'application/json')
        resp = {'message': u'配置修改成功'}
        return json.dumps(resp)
    except Exception, e:
        print str(e)
        status = '500 Internal Server Error'
        headers = {'Content-Type': 'application/json'}
        resp = json.dumps([{'message': u'系统错误'}])
        raise web.HTTPError(status, headers, unicode(resp))
            
class static:
    def GET(self, name):
        web.header("Content-Type", "text/plain; charset=utf-8")
        return open('static/%s' % name)
            
class about:
    def GET(self):
        global need_reboot
        
        return render.about(
            need_reboot=need_reboot,
        )
    
class proxy:
    def GET(self):
        global coordinator, need_reboot
        
        shadowsocks_methods = coordinator.IPC_shadowsocks_methods()
        return render.proxy(
            need_reboot=need_reboot,
            confdata=coordinator.get('confdata'),
            shadowsocks_methods=shadowsocks_methods
        )
    
class blacklist:
    def GET(self):
        global coordinator
        
        (_, bl_count, bl_date) = coordinator.IPC_blacklist_info()
        custom_bl = coordinator.IPC_get_custom_blacklist()
        custom_wl = coordinator.IPC_get_custom_whitelist()
        return render.blacklist(
            need_reboot=need_reboot,
            bl_count=bl_count,
            bl_date=bl_date,
            custom_bl=u"\n".join(custom_bl),
            custom_wl=u"\n".join(custom_wl),
        )
        
class hosts:
    def GET(self):
        global coordinator, need_reboot
        
        (_, enable, count, groups, date) = coordinator.IPC_hosts_info()
        return render.hosts(
            need_reboot=need_reboot,
            enable=enable,
            domain_count=count,
            groups=groups,
            hosts_date=date,
        )
        
    def POST(self):
        data = web.input()
        hosts = coordinator.get('confdata')['hosts'].copy()
        if data.get('enable'):
            hosts['enable'] = 1
        else:
            hosts['enable'] = 0
        update = {
            'hosts': hosts
        }
        return update_config(update, reboot=False, reload_hosts=True)
    
class localproxy_settings:
    def POST(self):
        global need_reboot, coordinator
        
        data = web.input()
        update = {}
        try:
            update['enable_http_proxy'] = 0
            if data.get('enable_http_proxy'):
                update['enable_http_proxy'] = 1
                    
            update['http_proxy_ip'] = data.get('http_proxy_ip')
            update['http_proxy_port'] = int(data.get('http_proxy_port'))
            
            update['enable_socks_proxy'] = 0
            if data.get('enable_socks_proxy'):
                update['enable_socks_proxy'] = 1
            update['socks_proxy_ip'] = data.get('socks_proxy_ip')
            update['socks_proxy_port'] = int(data.get('socks_proxy_port'))
        except Exception, e:
            print str(e)
            status = '400 Bad Request'
            headers = {'Content-Type': 'application/json'}
            resp = json.dumps([{'message': u'数据格式错误'}])
            raise web.HTTPError(status, headers, unicode(resp))
        
        return update_config(update)
        
class browser_settings:
    def POST(self):
        global need_reboot, coordinator
        
        data = web.input()
        update = {}
        update['launch_browser'] = 0
        update['home_page'] = data.get('home_page')
        if data.get('launch_browser'):
            update['launch_browser'] = 1
        return update_config(update, reboot=False)
    
class default_settings:
    def POST(self):
        global need_reboot, coordinator
        
        try:
            default = coordinator.IPC_resume_default_config()
            return update_config(default, reboot=True, ipc=False)
        except Exception, e:
            print str(e)
            status = '500 Internal Server Error'
            headers = {'Content-Type': 'application/json'}
            resp = json.dumps([{'message': u'系统错误'}])
            raise web.HTTPError(status, headers, unicode(resp))
    
class circumvention_settings:
    def POST(self):
        global need_reboot, coordinator
        
        data = web.input()
        update = {}
        try:
            update['circumvention_chan_type'] = data.get('circumvention_chan_type')
            update['circumvention_proxy_ip'] = data.get('circumvention_proxy_ip')
            update['circumvention_proxy_port'] = int(data.get('circumvention_proxy_port'))
            
            sshconfig = {}
            sshconfig['server_name'] = data.get('ssh_server_name')
            sshconfig['server_port'] = get_int(data, 'ssh_server_port', 0)
            sshconfig['username'] = data.get('ssh_username')
            sshconfig['password'] = data.get('ssh_password')
            sshconfig['keyfile'] = data.get('ssh_keyfile')
            sshconfig['auth'] = data.get('ssh_auth')
            update['circumvention_chan_ssh'] = sshconfig
            
            shadowsocks_config = {}
            shadowsocks_config['server_name'] = data.get('shadowsocks_server_name')
            shadowsocks_config['server_port'] = get_int(data, 'shadowsocks_server_port', 0)
            shadowsocks_config['password'] = data.get('shadowsocks_password')
            shadowsocks_config['method'] = data.get('shadowsocks_method')
            shadowsocks_config['timeout'] = get_int(data, 'shadowsocks_timeout', 0)
            shadowsocks_config['fast_open'] = 0
            if data.get('shadowsocks_fast_open'):
                shadowsocks_config['fast_open'] = 1
            
            update['circumvention_chan_shadowsocks'] = shadowsocks_config
        except Exception, e:
            print str(e)
            status = '400 Bad Request'
            headers = {'Content-Type': 'application/json'}
            resp = json.dumps([{'message': u'数据格式错误'}])
            raise web.HTTPError(status, headers, unicode(resp))
        
        return update_config(update)
    
class bl:
    def GET(self):
        global coordinator
        
        web.header("Content-Type", "text/plain; charset=utf-8")
        return open(coordinator.IPC_blacklist_info()[0])
    
    def POST(self):
        global coordinator
        
        if coordinator.IPC_update_blacklist():
            web.header('Content-Type', 'application/json')
            resp = {'message': u'黑名单更新成功，已生效'}
            return json.dumps(resp)
        else:
            status = '500 Internal Server Error'
            headers = {'Content-Type': 'application/json'}
            resp = json.dumps([{'message': u'系统错误'}])
            raise web.HTTPError(status, headers, unicode(resp))
    
class custom_bl:
    def POST(self):
        global coordinator
        
        try:
            data = web.input()
            custom_bl = data.get('custom_bl').split("\r\n")
            web.header('Content-Type', 'application/json')
            coordinator.IPC_update_custom_list(custom_bl=custom_bl)
            resp = {'message': u'自定义黑名单更新成功，已生效'}
            return json.dumps(resp)
        except:
            status = '500 Internal Server Error'
            headers = {'Content-Type': 'application/json'}
            resp = json.dumps([{'message': u'系统错误'}])
            raise web.HTTPError(status, headers, unicode(resp))
        
class custom_wl:
    def POST(self):
        global coordinator
        
        try:
            data = web.input()
            custom_wl = data.get('custom_wl').split("\r\n")
            web.header('Content-Type', 'application/json')
            coordinator.IPC_update_custom_list(custom_wl=custom_wl)
            resp = {'message': u'自定义白名单更新成功，已生效'}
            return json.dumps(resp)
        except:
            status = '500 Internal Server Error'
            headers = {'Content-Type': 'application/json'}
            resp = json.dumps([{'message': u'系统错误'}])
            raise web.HTTPError(status, headers, unicode(resp))
        
class hosts_data:
    def GET(self):
        global coordinator
        
        web.header("Content-Type", "text/plain; charset=utf-8")
        return open(coordinator.IPC_hosts_info()[0])
    
    def POST(self):
        global coordinator
        
        if coordinator.IPC_update_hosts():
            web.header('Content-Type', 'application/json')
            resp = {'message': u'Host 文件更新成功，已生效'}
            return json.dumps(resp)
        else:
            status = '500 Internal Server Error'
            headers = {'Content-Type': 'application/json'}
            resp = json.dumps([{'message': u'系统错误'}])
            raise web.HTTPError(status, headers, unicode(resp))
        
class hosts_group:
    def POST(self):
        global coordinator
        
        try:
            (_, _, _, groups, _) = coordinator.IPC_hosts_info()
            groups = [a[0] for a in groups]
            disabled = groups
            data = web.input().keys()
            for k in data:
                if k in groups:
                    disabled.remove(k)
            coordinator.IPC_update_hosts_disabled(disabled)
            web.header('Content-Type', 'application/json')
            resp = {'message': u'Host 配置更新成功，已生效'}
            return json.dumps(resp)
        except:
            status = '500 Internal Server Error'
            headers = {'Content-Type': 'application/json'}
            resp = json.dumps([{'message': u'系统错误'}])
            raise web.HTTPError(status, headers, unicode(resp))
               
               
def create_app(ref):
    global coordinator
    coordinator = ref
    return web.application(urls, globals(), autoreload=False).wsgifunc()

if __name__ == '__main__':
    web.application(urls, globals()).run()
   
    