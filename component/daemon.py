#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import webbrowser
from multiprocessing import Process

from lib.systray import SysTrayIcon
from lib.ipc import IPC_Process

class Daemon(IPC_Process):
    def __init__(self, hub_ref):
        super(Daemon, self).__init__()
        self.hub_ref = hub_ref
        
    def systray_quit(self, systray_ref):
        pass
    
    def sytray_launch_browser(self, systray_ref):
        self.hub_ref.IPC_launch_browser()
    
    def systray_open_webadmin(self, systray_ref):
        self.hub_ref.IPC_open_admin_url()
    
    def run(self):
        rootdir = self.hub_ref.get('rootdir')
        confdata = self.hub_ref.get('confdata')
        SysTrayIcon(
            os.path.join(rootdir, confdata['icon_path']),
            u'萤火虫翻墙代理',
            (
                (u'翻墙浏览', None, self.sytray_launch_browser),
                (u'配置代理', None, self.systray_open_webadmin),
                (u'退出', None, 'QUIT')
            ),
            on_quit=self.systray_quit,
            default_menu_index=1,
        )
    
        
        
        