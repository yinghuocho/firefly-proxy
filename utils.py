# basic routinues
import struct

from gevent import socket
from gevent import select

import msg

class ProtocolError(Exception): pass
class FormatError(Exception): pass

def readaddr(sock, addrtype):
    if addrtype == msg.IP_V4:
        return sock.recv(4)
    elif addrtype == msg.IP_V6:
        return sock.recv(16)
    elif addrtype == msg.DOMAIN_NAME:
        data1 = sock.recv(1)
        length = struct.unpack('B', data1)[0]
        data2 = sock.recv(length)
        return data1 + data2
    else:
        raise FormatError("Unknown address type %s" % addrtype.encode('hex'))

def read_init_request(sock):
    data1 = sock.recv(2)
    data2 = sock.recv(struct.unpack('B', data1[1])[0])
    initreq = msg.InitRequest(data1+data2)
    if initreq.version != msg.SOCKS5:
        raise ProtocolError("Unsupported version %s" % initreq.version.encode('hex'))
    return initreq

def read_init_reply(sock):
    data = sock.recv(2)
    initreply = msg.InitReply(data)
    return initreply

def init_reply(sock, method):
    sock.sendall(msg.InitReply(method=method).pack())

def init_fail(sock):
    init_reply(sock, msg.NO_ACCEPTABLE_METHODS)

def basic_handshake_client(sock):
    sock.sendall(msg.InitRequest().pack())
    initreply = read_init_reply(sock)
    if initreply.method != msg.NO_AUTHENTICATION_REQUIRED:
        return False
    return True

def basic_handshake_server(sock):
    initreq = read_init_request(sock)
    if initreq.version != msg.SOCKS5:
        return False
    if msg.NO_AUTHENTICATION_REQUIRED not in initreq.methods:
        init_fail(sock)
        return False
    
    init_reply(sock, msg.NO_AUTHENTICATION_REQUIRED)
    return True

def read_request(sock):
    data1 = sock.recv(4)
    data2 = readaddr(sock, data1[3])
    data3 = sock.recv(2)
    req = msg.Request(data1 + data2 + data3)
    return req

def send_request(sock, cmd, addrtype, dstaddr, dstport):
    sock.sendall(msg.Request(cmd=cmd, addrtype=addrtype, dstaddr=dstaddr, dstport=dstport).pack())

def read_reply(sock):
    data1 = sock.recv(4)
    data2 = readaddr(sock, data1[3])
    data3 = sock.recv(2)
    reply = msg.Reply(data1 + data2 + data3)
    return reply

def request_fail(sock, request, response):
    reply = msg.Reply(rep=response, addrtype=request.addrtype,
        bndaddr=request.dstaddr, bndport=request.dstport)
    sock.sendall(reply.pack())
    
def request_success(sock, addrtype, bndaddr, bndport):
    reply = msg.Reply(addrtype=addrtype,
        bndaddr=bndaddr, bndport=bndport)
    sock.sendall(reply.pack())
    
def pipe_tcp(local, remote, local_timeout, remote_timeout, bufsize=65536):
    rlist = [local, remote]
    local_timer = 0
    remote_timer = 0
    while True:
        readable, _, _ = select.select(rlist, [], [], timeout=1)
        if not readable:
            local_timer += 1
            remote_timer += 1
            if local_timer > local_timeout or remote_timer > remote_timeout:
                return
            else:
                continue
        
        if local in readable:
            local_timer = 0
            data = local.recv(bufsize)
            if not data:
                return
            remote.sendall(data)
            
        if remote in readable:
            remote_timer = 0
            data = remote.recv(bufsize)
            if not data:
                return
            local.sendall(data)

def pipe_udp(tcpsocks, csock, rsock, ctimeout, rtimeout,
                caddrchecker, c2r, r2c):
    rlist = tcpsocks + [csock, rsock]
    csock_timer = 0
    rsock_timer = 0
    while True:
        readable, _, _ = select.select(rlist, [], [], timeout=1)
        if not readable:
            csock_timer += 1
            rsock_timer += 1
            if csock_timer > ctimeout or rsock_timer > rtimeout:
                return    
            else:
                continue
           
        for s in tcpsocks: 
            if s in readable:
                return
            
        if csock in readable:
            csock_timer = 0
            fromdata, fromaddr = csock.recvfrom(65536)
            if caddrchecker(fromaddr[0], fromaddr[1]):
                todata, toaddr = c2r(fromdata, fromaddr)
                if todata and toaddr:
                    rsock.sendto(todata, toaddr)
                
        if rsock in readable:
            rsock_timer = 0
            fromdata, fromaddr = rsock.recvfrom(65536)
            todata, toaddr = r2c(fromdata, fromaddr)
            if todata and toaddr:
                csock.sendto(todata, toaddr)
                
def bind_local_udp(tcpsock):
    tcpaddr = tcpsock.getsockname()
    addrinfo = socket.getaddrinfo(tcpaddr[0], 0, 0, socket.SOCK_DGRAM, socket.SOL_UDP)  # @UndefinedVariable
    af, socktype, proto, _, localaddr = addrinfo[0]
    udpsock = socket.socket(af, socktype, proto)
    udpsock.bind(localaddr)
    return udpsock

def bind_local_sock_by_addr(addr):
    addrinfo = socket.getaddrinfo(addr[0], addr[1], 0, socket.SOCK_DGRAM, socket.SOL_UDP)  # @UndefinedVariable
    af, socktype, proto, _, remoteaddr = addrinfo[0]
    sock = socket.socket(af, socktype, proto)
    sock.connect(remoteaddr)
    return sock

def sock_addr_info(sock):
    addr = sock.getsockname()
    if len(addr) == 4:
        addrtype = msg.IP_V6
    else:
        addrtype = msg.IP_V4
    return addrtype, addr[0], addr[1]

def addr_info(addr):
    if len(addr) == 4:
        addrtype = msg.IP_V6
    else:
        addrtype = msg.IP_V4
    return addrtype, addr[0], addr[1]

def addr_type(addr):
    try:
        socket.inet_pton(socket.AF_INET, addr)  # @UndefinedVariable
        return msg.IP_V4
    except:
        pass

    try:
        socket.inet_pton(socket.AF_INET6, addr)  # @UndefinedVariable
        return msg.IP_V6
    except:
        pass
    return msg.DOMAIN_NAME
    
class SharedTimer(object):
    """ this timer can be shared by two greenlets
    """
    def __init__(self, to):
        self.to = to
        self.timer = 0
    def count(self, secs):
        self.timer += secs
    def reset(self):
        self.timer = 0
    def timeout(self):
        return self.timer > self.to   
