import os

from gevent import socket
from gevent.pywsgi import WSGIServer

from lib.ipc import ActorProcess
from lib.utils import idle_port, init_logging

class Admin(ActorProcess):
    def __init__(self, coordinator):
        super(Admin, self).__init__()
        self.coordinator = coordinator
        
        confdata = self.coordinator.get('confdata')
        self.ip = confdata['webadmin_ip']
        self.port = confdata['webadmin_port']
        
    def run(self):
        init_logging()
        rootdir = self.coordinator.get('rootdir')   
        confdata = self.coordinator.get('confdata')
        webpath = os.path.join(rootdir, confdata['web_path'])
        os.chdir(webpath)
        
        from webpanel import app
        try:
            svr = WSGIServer((self.ip, self.port), application=app.create_app(self.coordinator), log=None)
            svr.serve_forever()
        except socket.error, e:  # @UndefinedVariable
            print "failed to start web admin: %s, change port then try again" % str(e)
            self.port = idle_port()
            WSGIServer((self.ip, self.port), application=app.create_app(self.coordinator), log=None).serve_forever()
            
    def IPC_url(self):
        return "http://%s:%d/about" % (self.ip, self.port)
        
        

        
        
        
        