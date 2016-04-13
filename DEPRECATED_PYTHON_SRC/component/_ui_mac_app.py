# -*- coding: utf-8 -*-
import os
import rumps

class FireflyApp(rumps.App):
    def __init__(self, coordinator):
        self.coordinator = coordinator
        
        rootdir = self.coordinator.get('rootdir')
        confdata = self.coordinator.get('confdata')
        icon = os.path.join(rootdir, confdata['icon_path'])
        super(FireflyApp, self).__init__("Firefly", icon=icon, quit_button=None)
        self.menu = [u'翻墙浏览', u'配置代理']
        
    @rumps.clicked(u'配置代理')
    def config(self, _):
        self.coordinator.IPC_open_admin_url()
        
    @rumps.clicked(u'翻墙浏览')
    def surf(self, _):
        self.coordinator.IPC_launch_browser()
        
    @rumps.clicked(u'退出')
    def quit(self, _):
        self.coordinator.IPC_quit()
        rumps.quit_application()
        
        