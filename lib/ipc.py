import sys
import threading
from multiprocessing import Queue, Pipe, Process

if sys.platform == 'win32':
    from multiprocessing.reduction import reduce_pipe_connection as reduce_connection
    from multiprocessing.reduction import rebuild_pipe_connection as rebuild_connection
else:
    from multiprocessing.reduction import reduce_connection, rebuild_connection

class Actor(object):
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
        
    def _handle(self, msg_handlers):
        while True:
            (msg, args, kwargs, chan) = self.inbox.get()
            if msg == "quit":
                break
            try:
                handler = msg_handlers[msg]
                t = threading.Thread(target=self._do, args=(handler, chan, args, kwargs))
                t.daemon = True
                t.start() 
            except:
                pass
            
    def _start(self, holder):
        msg_handlers = dict(
            [(m, getattr(holder, m)) for m in dir(holder) if m.startswith("IPC_")]
        )
        t = threading.Thread(target=self._handle, args=(msg_handlers,))
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
        
class ActorObject(object):
    def __init__(self):
        self._ref = Actor()
        
    def start_actor(self):
        self._ref._start(self)
        
    def quit_actor(self):
        self._ref._quit()
        
    def ref(self):
        return self._ref
    
class ActorProcess(ActorObject):
    def __init__(self):
        super(ActorProcess, self).__init__()
        self.process = None
    
    def _run(self):
        # in child process, start IPC_ref, so parent can invoke IPC_xxx interfaces.
        self.start_actor()
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
        self.quit_actor()
        if self.process:
            self.process.terminate()
        
    def is_alive(self):
        if self.process:
            return self.process.is_alive()
        else:
            return False
        
if __name__ == "__main__":
    import time
    import os
    class P1(ActorProcess):
        def run(self):
            while True:
                time.sleep(1)
                
        def IPC_hello(self):
            return "Hello, I am P1 running at " + str(os.getpid())
            
    class P2(ActorProcess):
        def run(self):
            while True:
                time.sleep(1)
    
        def IPC_hello(self):
            return "Hello, I am P2 running at " + str(os.getpid())
        
    class O1(ActorObject):
        def IPC_hello(self):
            return "Hello, I am O3 running at " + str(os.getpid())
    
    p1 = P1()
    p2 = P2()
    p1.start()
    p2.start()
    print "main process %d" % os.getpid()
    print p1.ref().IPC_hello()
    print p2.ref().IPC_hello()
    p1.terminate()
    p1.join()
    p2.terminate()
    p2.join()
    
    o1 = O1()
    o1.start_actor()
    print o1.ref().IPC_hello()
        
