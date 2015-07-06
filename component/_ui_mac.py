import os

from lib.ipc import ActorObject

class UI(ActorObject):
    def __init__(self, coordinator):
        super(UI, self).__init__()
        self.coordinator = coordinator
        
    def run(self):
        try:
            # due to some bugs, the import must goes after Process.start
            # see this link: http://stackoverflow.com/questions/21143866/python-tkinter-application-causes-fork-exec-error-on-mac-os-x 
            self.start_actor()
            from component._ui_mac_app import FireflyApp
            app = FireflyApp(self.coordinator)
            app.run()
            self.quit_actor()
        except Exception, e:
            print e
        