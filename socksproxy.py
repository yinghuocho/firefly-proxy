# a socks5 proxy
import logging
import sys
import os
from sys import platform as _platform
if _platform == "linux" or _platform == "linux2":
    os.environ['GEVENT_RESOLVER'] = "ares"

from relay import SocksRelayFactory
from server import SocksServer

def usage(f):
    print >> f, """
Usage: python proxy.py localip localport
    """

def main():
    if len(sys.argv) < 3:
        usage(f=sys.stderr)
        sys.exit(-1)
        
    logging.basicConfig(
        format='[%(asctime)s][%(name)s][%(levelname)s] - %(message)s',
        datefmt='%Y-%d-%m %H:%M:%S',
        level=logging.DEBUG, 
    )
    localip = sys.argv[1]
    localport = int(sys.argv[2])
    relayfactory = SocksRelayFactory()
    socks = SocksServer(localip, localport, relayfactory)
    socks.run()
    
if __name__ == '__main__':
    main()
    