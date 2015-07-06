# -*- coding: utf-8 -*-

import os

from lib.ipc import ActorProcess
from lib.systray import SysTrayIcon
from lib.utils import init_logging

class UI(ActorProcess):
    def __init__(self, coordinator):
        super(UI, self).__init__()
        self.coordinator = coordinator
        
    def systray_quit(self, systray_ref):
        pass
    
    def sytray_launch_browser(self, systray_ref):
        self.coordinator.IPC_launch_browser()
    
    def systray_open_webadmin(self, systray_ref):
        self.coordinator.IPC_open_admin_url()
        
    def run(self):
        init_logging()
        self.start_actor()
        rootdir = self.coordinator.get('rootdir')
        confdata = self.coordinator.get('confdata')
        icon = os.path.join(rootdir, confdata['icon_path']) 
        SysTrayIcon(
            icon,
            u'萤火虫翻墙代理',
            (
                (u'翻墙浏览', None, self.sytray_launch_browser),
                (u'配置代理', None, self.systray_open_webadmin),
                (u'退出', None, 'QUIT')
            ),
            on_quit=self.systray_quit,
            default_menu_index=1,
        )
        self.quit_actor()
    