# forward local socks to remote socks
import logging
import sys
import os
from sys import platform as _platform
if _platform == "linux" or _platform == "linux2":
    os.environ['GEVENT_RESOLVER'] = "ares"

from socks_relay import SocksForwardFactory
from server import SocksServer

def usage(f):
    print >> f, """
Usage: python forwarder.py localip localport remoteip remoteport
    """

def main():
    if len(sys.argv) < 5:
        usage(f=sys.stderr)
        sys.exit(-1)
    
    localip = sys.argv[1]
    localport = sys.argv[2]
    remoteip = sys.argv[3]
    remoteport = sys.argv[4]
    
    logging.basicConfig(
        format='[%(asctime)s][%(name)s][%(levelname)s] - %(message)s',
        datefmt='%Y-%d-%m %H:%M:%S',
        level=logging.DEBUG,    
    )
    forwardfactory = SocksForwardFactory(remoteip, remoteport)
    socks = SocksServer(localip, localport, forwardfactory)
    socks.run()

if __name__ == '__main__':
    main()