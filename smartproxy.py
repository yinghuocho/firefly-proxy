# a socks5 proxy with rule-based forwarding
import logging
import sys
import os
import re
from urlparse import urlparse
from sys import platform as _platform
if _platform == "linux" or _platform == "linux2":
    os.environ['GEVENT_RESOLVER'] = "ares"

from smart_relay import SmartRelayFactory
from match import SocksForwardRegexMatch
from server import SocksServer

def usage(f):
    print >> f, """
Usage: python smartproxy.py localip localport
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
    
    rules = {
        (re.compile(r'.*\.whereisip\.net$'), re.compile(r'.*'), re.compile(r'.*')): urlparse('socks5://127.0.0.1:1080/'),
        (re.compile(r'.*\.google\.com$'), re.compile(r'.*'), re.compile(r'.*')): urlparse('socks5://127.0.0.1:1080/'),
    }
    match = SocksForwardRegexMatch(rules)
    relay = SmartRelayFactory(match)
    socks = SocksServer(localip, localport, relay)
    socks.run()

if __name__ == '__main__':
    main()
    
    