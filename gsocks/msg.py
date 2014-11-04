# socks5 packet format
import os
import struct

from gevent import socket
import dpkt

if os.name == 'nt':
    import win_inet_pton
    socket.inet_pton = win_inet_pton.inet_pton
    socket.inet_ntop = win_inet_pton.inet_ntop

# version
SOCKS5 = '\x05'

# reserve
RSV = '\x00'

# command
CONNECT         = '\x01'
BIND            = '\x02'
UDP_ASSOCIATE   = '\x03'

# methods
NO_AUTHENTICATION_REQUIRED  = '\x00'
NO_ACCEPTABLE_METHODS       = '\xff' 

# address type
IP_V4       = '\x01'
DOMAIN_NAME = '\x03'
IP_V6       = '\x04'

# reply
SUCCEEDED                       = '\x00'
GENERAL_SOCKS_SERVER_FAILURE    = '\x01'
CONNECT_NOT_ALLOWED             = '\x02'
NETWORK_UNREACHABLE             = '\x03'
CONNECTION_REFUSED              = '\x04'
TTL_EXPIRED                     = '\x06'
CMD_NOT_SUPPORTED               = '\x07'
ADDR_TYPE_NOT_SUPPORTED         = '\x08'
        
def pack_addr(addrtype, addr):
    if addrtype == IP_V4:
        s = socket.inet_pton(socket.AF_INET, addr)
    elif addrtype == IP_V6:
        s = socket.inet_pton(socket.AF_INET6, addr)
    elif addrtype == DOMAIN_NAME:
        s = struct.pack('B', len(addr))
        s += addr
    else:
        raise dpkt.PackError("Unknown address type %s" % addrtype.encode('hex'))
    return s

def unpack_addr(addrtype, buf, offset):
    if addrtype == IP_V4:
        addr = socket.inet_ntop(socket.AF_INET, buf[offset:(offset+4)])
        nxt = offset+4
    elif addrtype == IP_V6:
        addr = socket.inet_ntop(socket.AF_INET6, buf[offset:(offset+16)])
        nxt = offset+16
    elif addrtype == DOMAIN_NAME:
        length = struct.unpack('B', buf[offset])[0]
        addr = buf[(offset+1):(offset+1+length)]
        nxt = offset+1+length
    else:
        raise dpkt.UnpackError("Unknown address type %s" % addrtype.encode('hex'))
    return addr, nxt
        
class InitRequest(dpkt.Packet):
    __hdr__ = (
        ('version', 'c', SOCKS5),
        ('nmethods', 'B', 1),
        ('methods', 's', NO_AUTHENTICATION_REQUIRED),
    )
    
    def pack(self):
        return self.version + struct.pack('B', self.nmethods) + self.methods
    
    def unpack(self, buf):
        self.version = buf[0]
        self.nmethods = struct.unpack('B', buf[1])[0]
        self.methods = buf[2:(2+self.nmethods)]
        
        
class InitReply(dpkt.Packet):
    __hdr__ = (
        ('version', 'c', SOCKS5),
        ('method', 'c', NO_AUTHENTICATION_REQUIRED),
    )
    
class Request(dpkt.Packet):
    __hdr__ = (
        ('version', 'c', SOCKS5),
        ('cmd', 'c', CONNECT),
        ('rsv', 'c', RSV),
        ('addrtype', 'c', IP_V4),
        ('dstaddr', 's', ''),
        ('dstport', 'H', 0x3003),
    )
    
    def pack(self):
        addr = pack_addr(self.addrtype, self.dstaddr)
        return self.version + self.cmd + self.rsv + \
                    self.addrtype + addr + struct.pack('!H', self.dstport)

    def unpack(self, buf):
        self.version = buf[0]
        self.cmd = buf[1]
        self.rsv = buf[2]
        self.addrtype = buf[3]
        
        self.dstaddr, offset = unpack_addr(self.addrtype, buf, 4)
        self.dstport = struct.unpack('!H', buf[offset:(offset+2)])[0]

      
class Reply(dpkt.Packet):
    __hdr__ = (
        ('version', 'c', SOCKS5),
        ('rep', 'c', SUCCEEDED),
        ('rsv', 'c', RSV),
        ('addrtype', 'c', IP_V4),
        ('bndaddr', 's', ''),
        ('bndport', 'H', 0x3003),
    )
    
    def pack(self):
        addr = pack_addr(self.addrtype, self.bndaddr)
        return self.version + self.rep + self.rsv + \
                    self.addrtype + addr + struct.pack('!H', self.bndport)

    def unpack(self, buf):
        self.version = buf[0]
        self.rep = buf[1]
        self.rsv = buf[2]
        self.addrtype = buf[3]
        self.bndaddr, offset = unpack_addr(self.addrtype, buf, 4)
        self.bndport = struct.unpack('!H', buf[offset:(offset+2)])[0]
        

class UDPRequest(dpkt.Packet):
    __hdr__ = (
        ('rsv', '2s', RSV+RSV),
        ('frag', 'c', '\x00'),
        ('addrtype', 'c', IP_V4),
        ('dstaddr', 's', ''),
        ('dstport', 'H', 0x3003),
    )
    
    def pack(self):
        addr = pack_addr(self.addrtype, self.dstaddr)
        return self.rsv + self.frag + self.addrtype \
                    + addr + struct.pack('!H', self.dstport) + self.data 
    
    def unpack(self, buf):
        self.rsv = buf[0:2]
        self.frag = buf[2]
        self.addrtype = buf[3]
        self.dstaddr, offset = unpack_addr(self.addrtype, buf, 4)
        self.dstport = struct.unpack('!H', buf[offset:(offset+2)])[0]
        self.data = buf[(offset+2):]
        
    


