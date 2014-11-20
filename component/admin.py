import os

from gevent import socket
from gevent.pywsgi import WSGIServer

from lib.ipc import IPC_Process
from lib.utils import idle_port

class Webadmin(IPC_Process):
    def __init__(self, hub_ref):
        super(Webadmin, self).__init__()
        self.hub_ref = hub_ref
        
        confdata = self.hub_ref.get('confdata')
        self.ip = confdata['webadmin_ip']
        self.port = confdata['webadmin_port']
        
    def IPC_url(self):
        return "http://%s:%d/about" % (self.ip, self.port)
    
    def run(self):
        rootdir = self.hub_ref.get('rootdir')
        confdata = self.hub_ref.get('confdata')
        webpath = os.path.join(rootdir, confdata['web_path'])
        os.chdir(webpath)
        
        from webui import app
        try:
            WSGIServer((self.ip, self.port), application=app.create_app(self.hub_ref), log=None).serve_forever()
        except socket.error, e:  # @UndefinedVariable
            print "failed to start web admin: %s, change port then try again" % str(e)
            self.port = idle_port()
            WSGIServer((self.ip, self.port), application=app.create_app(self.hub_ref), log=None).serve_forever()
        
        