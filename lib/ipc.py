import sys
import threading
from multiprocessing import Queue, Pipe, Process

if sys.platform == 'win32':
    from multiprocessing.reduction import reduce_pipe_connection as reduce_connection
    from multiprocessing.reduction import rebuild_pipe_connection as rebuild_connection
else:
    from multiprocessing.reduction import reduce_connection, rebuild_connection

class IPC_Reference(object):
    def __init__(self):
        self.inbox = Queue()
        self.shared_data = {}
        
    def share(self, name, value):
        self.shared_data[name] = value
        
    def get(self, name):
        return self.shared_data.get(name, None)
        
    def _ask(self, msg, args=(), kwargs={}):
        i, o = Pipe()
        reduced = reduce_connection(i)
        self.inbox.put([msg, args, kwargs, reduced[1]])
        ret = o.recv()
        i.close()
        o.close()
        return ret
        
    def _do(self, handler, chan, args, kwargs):
        try:
            ret = handler(*args, **kwargs)
            if chan:
                chan = rebuild_connection(*chan)
                chan.send(ret)
                chan.close()
        except Exception, e:
            if chan:
                chan = rebuild_connection(*chan)
                chan.send(e)
                chan.close()
        
    def _handle(self, ipc_handlers):
        while True:
            (msg, args, kwargs, chan) = self.inbox.get()
            if msg == "quit":
                break
            try:
                handler = ipc_handlers[msg]
                # bad performance, but makes IPC re-enterable 
                t = threading.Thread(target=self._do, args=(handler, chan, args, kwargs))
                t.daemon = True
                t.start() 
            except:
                pass
            
    def _start(self, host):
        ipc_handlers = dict(
            [(m, getattr(host, m)) for m in dir(host) if m.startswith("IPC_")]
        )
        t = threading.Thread(target=self._handle, args=(ipc_handlers,))
        t.daemon = True
        t.start()
        
    def _quit(self):
        self.inbox.put(["quit", (), {}, None])
        
    def __getattr__(self, name):
        def _(*args, **kwargs):
            return self._ask(name, args, kwargs)
        
        if name.startswith("IPC_"):
            return _
        else:
            raise AttributeError
        
class IPC_Host(object):
    def __init__(self):
        self._ref = IPC_Reference()
        
    def start_IPC(self):
        self._ref._start(self)
        
    def quit_IPC(self):
        self._ref._quit()
        
    def ref(self):
        return self._ref
    
class IPC_Process(IPC_Host):
    def __init__(self):
        super(IPC_Process, self).__init__()
        self.process = None
    
    def _run(self):
        # in child process, start IPC_ref, so parent can invoke IPC_xxx interfaces.
        self.start_IPC()
        self.run()
    
    def run(self):
        raise NotImplementedError
    
    def start(self):
        self.process = Process(target=self._run)
        self.process.daemon = True
        self.process.start()
    
    def join(self):
        if self.process:
            self.process.join()
        
    def terminate(self):
        self.quit_IPC()
        if self.process:
            self.process.terminate()
        
    def is_alive(self):
        if self.process:
            return self.process.is_alive()
        else:
            return False
        
