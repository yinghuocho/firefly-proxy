# a socks proxy forwarding to a remote socks through meek (i.e., HTTP transport)
import logging
import os
import sys
from sys import platform as _platform
if _platform == "linux" or _platform == "linux2":
    os.environ['GEVENT_RESOLVER'] = "ares"

from server import SocksServer
from meek_relay import MeekRelayFactory, Relay

def usage(f):
    print >> f, """
Usage: python meeksocks-client.py localip localport relays

    Format of relays:
        url1,host1,property1:property2|url2,host2,|...
    
    Example:
        https://www.google.com/,firefly-relay-1.appspot.com,stream
        
"""

def main():
    if len(sys.argv) < 4:
        usage(f = sys.stderr)
        sys.exit(-1)
        
    localip = sys.argv[1]
    localport = int(sys.argv[2])
    relays = []
    for entry in sys.argv[3].split("|"):
        fronturl, hostname, properties = entry.split(",")
        properties = properties.split(":")
        relays.append(Relay(
            fronturl=fronturl, hostname=hostname, properties=properties, failure=0))
    
    logging.basicConfig(
        format='[%(asctime)s][%(name)s][%(levelname)s] - %(message)s',
        datefmt='%Y-%d-%m %H:%M:%S',
        level=logging.DEBUG,    
    )
    meekfactory = MeekRelayFactory(relays)
    socks = SocksServer(localip, localport, meekfactory)
    socks.run()

if __name__ == '__main__':
    main()
