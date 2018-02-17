#!/usr/bin/env python3
import sys
import socket
import random
import struct
import select
import string
import logging
import argparse
from os import linesep
from ctypes import Structure, BigEndianStructure, LittleEndianStructure, c_uint16

'''
Win7 name resolution order: hosts, DNS, LLMNR, NetBIOS
'''

LLMNR_PORT=5355
LLMNR_GRP='224.0.0.252'         # this is the multicast address reserved for LLMNR
MDNS_PORT=5353
MDNS_GRP='224.0.0.251'          # multicast DNS

class NBNSFlags(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('response', c_uint16, 1), # response or reply
        ('opcode', c_uint16, 4),
        ('reserved2', c_uint16, 1),
        ('truncated', c_uint16, 1),
        ('recursion', c_uint16, 1),
        ('reserved1', c_uint16, 3),
        ('broadcast', c_uint16, 1),
        ('reserved', c_uint16, 4),
    ]
    def __str__(self):
        return '''
response {}
opcode 0x{:02x}
reserved2 {}
truncated {}
recursion {}
reserved1 {}
broadcast {}
reserved 0x{:02x}
'''

class NetBIOSNameQuery():
    qmap = {'NB':0x20, 'IN':1}
    def __init__(self, hostname, qtype='NB', qclass='IN', srv_type=0x00):
        self.srv_type = srv_type
        self.trans_id = random.randint(1, 0xfffe)
        self.flags = NBNSFlags()
        self.flags.broadcast = 1
        self.flags.recursion = 1
        self.questions = 1
        self.answers = 0
        self.authority = 0
        self.additional = 0
        self.length = len(hostname)
        self.hostname = hostname
        self.qtype = NetBIOSNameQuery.qmap[qtype]
        self.qclass = NetBIOSNameQuery.qmap[qclass]
    def encode_name(self, name):
        name += ' ' * (15 - len(name)) # pad with spaces
        name += chr(self.srv_type)
        nibbles = [(b&0xf, b>>4&0xf) for b in name.encode()]
        e = b'\x20'                    # static length field
        for n in nibbles:
            e += struct.pack('BB', 0x41 + n[1], 0x41 + n[0])
        return e + b'\x00'
    def to_bytes(self):
        return struct.pack('>H', self.trans_id) + self.flags + \
            struct.pack('>HHHH', self.questions, self.answers, self.authority, self.additional) + \
            self.encode_name(self.hostname) + struct.pack('>HH', self.qtype, self.qclass)

class NetBIOSNameResponse():
    def __init__(self, data):
        self.trans_id = struct.unpack('>H', data[0:2])[0]
        self.flags = NBNSFlags.from_buffer_copy(data[2:4])
        self.questions, self.answers, self.authority, self.additional  = \
            struct.unpack('>HHHH', data[4:12])
        self.addrs = []
        answers = data[12:]
        for i in range(self.answers):
            length = answers[0]
            name, srv_type = self.decode_name(answers[1:1+length])
            qtype, qclass, ttl, dlen, flags = struct.unpack('>HHLHH', answers[2+length:2+length+12])
            addr = socket.inet_ntoa(answers[2+length+12:2+length+12+dlen])
            self.addrs.append(addr)
            answers = answers[2+length+10+dlen:]
    def decode_name(self, e):
        name = ''
        for i in range(0, len(e), 2):
            v = ((e[i+0]-0x41)<<4) | (e[i+1]-0x41)
            if v == ord(' '): break # break on padding space character
            name += chr(v)
        return name, ((e[-3]-0x41)<<4) | (e[-2]-0x41) # return name and service type


class DNSHeader(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('trans_id', c_uint16),
        # START flags
        ('response', c_uint16, 1), # query or response
        ('opcode', c_uint16, 4),
        ('aa', c_uint16, 1), # responding name server is authoritative
        ('tc', c_uint16, 1), # truncated
        ('rd', c_uint16, 1), # recursion desired
        ('ra', c_uint16, 1), # recursion available
        ('reserved', c_uint16, 2),
        ('auth', c_uint16, 1),  # non-auth data acceptable
        ('rcode', c_uint16, 4), # (0 good) (1 fmt err) (2 server err) (3 name err) (4 not impl) (5 refused)
        # END flags
        ('qdcount', c_uint16),  # query count
        ('ancount', c_uint16),  # answer count
        ('nscount', c_uint16),  # name server count
        ('arcount', c_uint16),  # addtl count
        # followed by resource records
    ]
    def to_bytes(self):
        return bytes(self)
    def __str__(self):
        return '''
trans_id 0x{:04x}
response {}
opcode 0x{:01x}
aa {}
tc {}
rd {}
ra {}
reserved {}
auth {}
rcode {:01x}
qdcount {}
ancount {}
nscount {}
arcount {}
'''.format(self.trans_id, self.response, self.opcode, self.aa, self.tc, self.rd, self.ra, self.reserved,
           self.auth, self.rcode, self.qdcount, self.ancount, self.nscount, self.arcount)


class DNSQuery():
    pass

class DNSReponse():
    pass

def encode_dns_name(name):
    e = b''
    for n in name.split('.'):
        e += int.to_bytes(len(n), 1, byteorder='big') + n.encode()
    return e + b'\x00'

def decode_dns_name(e):
    name = ''
    i = 0
    while e[i] != 0:
        name += e[i+1:i+e[i]+1].decode() + '.'
        i += e[i]+1
    return name[:-1]

record_type_map = {
    'A':1,
    'CNAME':5,
    'PTR':12,
    'AAAA':28,
}

class DNSResourceRecord():
    ''' https://www.ietf.org/rfc/rfc1035.txt '''
    def __init__(self, *, data=None, response=False):
        self.rname = ''
        self.rtype = 1          # A
        self.rclass = 1         # IN
        self.ttl = 60*60        # 1 hour
        self.rlen = 0           # rdata length
        self.rdata = ''
        if data:
            self.rname = decode_dns_name(data)
            data = data[data.find(b'\x00')+1:]
            self.rtype, self.rclass = struct.unpack('>HH', data[:4])
            data = data[4:]
            if response:
                self.ttl, self.rlen = struct.unpack('>LH', data[:6])
                data = data[6:]
                self.rdata = data[:self.rlen]
    def __len__(self):
        return len(self.rname) + 2 + 2 + 6 + len(self.rdata)
    def to_bytes(self):
        self.rlen = len(self.rdata)
        data = encode_dns_name(self.rname) + struct.pack('>HH', self.rtype, self.rclass)
        if self.rlen:
            data += struct.pack('>LH', self.ttl, self.rlen) + self.rdata
        return data
    def __str__(self):
        response = (self.rlen > 0)
        if self.rtype == record_type_map['A']:
            if response:
                return socket.inet_ntop(socket.AF_INET, self.rdata)
            else:
                return self.rname
        elif self.rtype == record_type_map['AAAA']:
            if response:
                return socket.inet_ntop(socket.AF_INET6, self.rdata)
            else:
                return self.rname
        elif self.rtype == record_type_map['PTR']:
            pass
        raise NotImplementedError

class MDNSHeader(DNSHeader):
    ''' NOTE: trans_id should be zero for multicast responses 
    https://tools.ietf.org/html/rfc6762#section-18.1 '''
    pass

class MDNSResourceRecord(DNSResourceRecord):
    def __init__(self, *, data=None, response=False):
        super().__init__(data=data, response=response)
        if data:
            self.cache_flush = self.rclass >> 15
            self.rclass = self.rclass & 0x7f

class MDNSData():
    def __init__(self, data=None):
        self.header = None
        self.queries = []
        self.answers = []
        self.authorities = []
        self.additionals = []
        if data:
            self.header = MDNSHeader.from_buffer_copy(data[:12])
            data = data[12:]
            for i in range(self.header.qdcount):
                rr = MDNSResourceRecord(data=data, response=self.header.response)
                self.queries.append(rr)
                data = data[len(rr):]
            for i in range(self.header.ancount):
                rr = MDNSResourceRecord(data=data, response=self.header.response)
                self.answers.append(rr)
                data = data[len(rr):]
            for i in range(self.header.nscount):
                rr = MDNSResourceRecord(data=data, response=self.header.response)
                self.authorities.append(rr)
                data = data[len(rr):]
            for i in range(self.header.arcount):
                rr = MDNSResourceRecord(data=data, response=self.header.response)
                self.additionals.append(rr)
                data = data[len(rr):]
        else:
            self.header = MDNSHeader()
    def to_bytes(self):
        data = b''
        self.header.qdcount = len(self.queries)
        for rr in self.queries:
            data += rr.to_bytes()
        self.header.ancount = len(self.answers)
        for rr in self.answers:
            data += rr.to_bytes()
        self.header.nscount = len(self.authorities)
        for rr in self.authorities:
            data += rr.to_bytes()
        self.header.arcount = len(self.additionals)
        for rr in self.additionals:
            data += rr.to_bytes()
        return self.header.to_bytes() + data
    def __str__(self):
        s = str(self.header)
        for records in [self.queries, self.answers, self.authorities, self.additionals]:
            for r in records:
                s += str(r) + linesep
        return s


class MDNSQuery(MDNSData):
    def __init__(self, *, data=None):
        super().__init__(data)
        if not data:
            self.header.response = 0
            self.header.trans_id = random.randint(1, 0xfffe)
    def to_bytes(self):
        return super().to_bytes()


class MDNSResponse(MDNSData):
    def __init__(self, data=None):
        super().__init__(data)
        if not data:
            self.header.response = 1


class LLMNRFlags(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('response', c_uint16, 1),
        ('opcode', c_uint16, 4),
        ('conflict', c_uint16, 1),
        ('truncated', c_uint16, 1),
        ('tentative', c_uint16, 1),
        ('reserved', c_uint16, 4),
        ('reply_code', c_uint16, 4),
    ]
    def __str__(self):
        return '''
ReplyCode {}
Tentative {}
Truncated {}
Conflict  {}
Opcode    {}
Response  {}
'''.format(self.reply_code, self.tentative, self.truncated, self.conflict, self.opcode, self.response)


class LLMNRQuery():
    qmap = {'A':1, 'IN':1}
    def __init__(self, hostname, qtype='A', qclass='IN'):
        self.trans_id = random.randint(1, 0xfffe)
        self.flags = LLMNRFlags()
        self.questions = 1
        self.answers = 0
        self.authority = 0
        self.additional = 0
        self.length = len(hostname)
        self.hostname = hostname + '\x00'
        self.qtype = LLMNRQuery.qmap[qtype]
        self.qclass = LLMNRQuery.qmap[qclass]
    def to_bytes(self):
        return struct.pack('>H', self.trans_id) + self.flags + \
            struct.pack('>HHHHB', self.questions, self.answers, self.authority, self.additional, self.length) + \
            self.hostname.encode() + struct.pack('>HH', self.qtype, self.qclass)

class LLMNRResponse():
    qmap = {'A':1, 'IN':1}
    def __init__(self, data):
        self.trans_id = struct.unpack('>H', data[0:2])[0]
        self.flags = LLMNRFlags.from_buffer_copy(data[2:4])
        self.questions, self.answers, self.authority, self.additional = \
            struct.unpack('>HHHH', data[4:12])
        questions = data[12:]
        for i in range(self.questions):
            length = questions[0]
            questions = questions[length+6:]
        self.addrs = []
        answers = questions
        for i in range(self.answers):
            length = answers[0]
            hostname = answers[1:1+length]
            qtype, qclass, ttl, dlen = struct.unpack('>HHLH', answers[2+length:2+length+10])
            addr = socket.inet_ntoa(answers[2+length+10:2+length+10+dlen])
            self.addrs.append(addr)
            answers = answers[2+length+10+dlen:]

def send_mdns(hostname, timeout=1, qtype='A', qclass='IN'):
    q = MDNSQuery()
    rr = MDNSResourceRecord()
    rr.rname = hostname
    q.queries.append(rr)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    s.sendto(q.to_bytes(), (MDNS_GRP, MDNS_PORT))
    logging.debug('mDNS Query "{}", TransID 0x{:04x}'.format(hostname, q.header.trans_id))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.bind(('', MDNS_PORT))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, struct.pack('=4sl', socket.inet_aton(MDNS_GRP), socket.INADDR_ANY))
    if s in select.select([s], [], [], timeout)[0]:
        data, addr = s.recvfrom(1024)
        a = MDNSResponse(data)
        logging.debug('mDNS Response from {}, TransId 0x{:04x}, Answer {}'.format(addr[0], a.header.trans_id, socket.inet_ntoa(a.answers[0].rdata)))
        return a
    return None

def send_llmnr(hostname, timeout=1, qtype='A', qclass='IN'):
    q = LLMNRQuery(hostname)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    s.sendto(q.to_bytes(), (LLMNR_GRP, LLMNR_PORT))
    logging.debug('LLMNR Query "{}", TransID 0x{:04x}'.format(hostname, q.trans_id))
    if s in select.select([s], [], [], timeout)[0]:
        data, addr = s.recvfrom(1024)
        a = LLMNRResponse(data)
        logging.debug('LLMNR Response from {}, TransId 0x{:04x}, Answer {}'.format(addr[0], a.trans_id, a.addrs[0]))
        if a.trans_id == q.trans_id:
            return a
    return None

def random_hostname(length=15):
    return random.choice(string.ascii_letters) + \
        ''.join([random.choice(string.ascii_letters+string.digits+'--') for i in range(14)])


def send_nbns(hostname, interface, timeout=1, qtype='NB', qclass='IN', srv_type=0x00):
    q = NetBIOSNameQuery(hostname, srv_type=srv_type)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    bcast = get_bcast_addr(interface)
    s.sendto(q.to_bytes(), (bcast, 137))
    logging.debug('NetBIOS Query "{}", TransID 0x{:04x}, bcast {}'.format(hostname, q.trans_id, bcast))
    if s in select.select([s], [], [], timeout)[0]:
        data, addr = s.recvfrom(1024)
        r = NetBIOSNameResponse(data)
        logging.debug('NetBIOS Response from {}, TransId 0x{:04x}, Answer {}'.format(addr[0], r.trans_id, r.addrs[0]))
        if r.trans_id == q.trans_id:
            return r
    return None

def get_bcast_addr(interface):
    try:
        # check if we have an IP already
        socket.inet_aton(interface)
        return interface
    except Exception:
        pass
    for line in open('/proc/net/route'):
        iface, dest, gw, flags, refcnt, use, metric, mask = line.split()[:8]
        if iface == interface and gw == '00000000' and dest != '0000FEA9':
            net = int(dest, 16)
            host = net | ((2**32-1)-int(mask, 16))
            return socket.inet_ntoa((net | host).to_bytes(4, byteorder='little'))
    raise RuntimeError('failed to find broadcast address for interface')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--responder', action='store_true', help='detect responder')
    parser.add_argument('-t', '--timeout', type=int, default=1, help='response timeout. default 1')
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug output')
    parser.add_argument('--type', dest='qtype', type=str.upper,
                        help='query type. defaults LLMNR => A, NetBIOS => NB')
    parser.add_argument('--class', dest='qclass', default='IN', type=str.upper,  help='query class. default IN')
    parser.add_argument('hostnames', nargs='*', help='hostnames to resolve')
    parser.add_argument('--service', type=lambda x:int(x, 16), default=0x00,
                        help='NetBIOS service type. default is 0x00 (Workstation)')
    parser.add_argument('--service-types', dest='srvtypes', action='store_true',
                        help='List all NetBIOS service types and exit')
    proto = parser.add_mutually_exclusive_group()
    proto.add_argument('--llmnr', action='store_true', help='use LLMNR. default')
    proto.add_argument('--mdns', action='store_true', help='use mDNS')
    proto.add_argument('--netbios', help='use NetBIOS NS. must specify interface or bcast address')
    args = parser.parse_args()

    if args.srvtypes:
        print('''
        NetBIOS Service Types https://en.wikipedia.org/wiki/NetBIOS#NetBIOS_Suffixes
          00: Workstation Service (workstation name)
          03: Windows Messenger service
          06: Remote Access Service
          20: File Service (also called Host Record)
          21: Remote Access Service client
          1B: Domain Master Browser – Primary Domain Controller for a domain
          1C: Domain Controllers. hostname should be domain common name
          1D: Master Browser
        ''')
        sys.exit(0)

    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s]:%(lineno)s %(message)s')
    if not any([args.llmnr, args.netbios, args.mdns]):
        args.llmnr = True
    if len(args.hostnames) == 0 and not args.responder:
        print('must specify a name to resolve or use --responder')
        sys.exit(1)

    if args.netbios:
        args.qtype = args.qtype or 'NB'
    elif args.llmnr:
        args.qtype = args.qtype or 'IN'

    if args.responder:
        if args.netbios:
            a1 = send_nbns(random_hostname(), args.netbios, args.timeout)
            if a1:
                a2 = send_nbns(random_hostname(), args.netbios, args.timeout)
                if a2:
                    if a1.addrs[0] == a2.addrs[0]:
                        print('[!] Responder detected with NetBIOS. Poisoned answer resolves to '+a1.addrs[0])
        elif args.llmnr:
            a1 = send_llmnr(random_hostname(), args.timeout)
            if a1:
                a2 = send_llmnr(random_hostname(), args.timeout)
                if a2:
                    if a1.addrs[0] == a2.addrs[0]:
                        print('[!] Responder detected with LLMNR. Poisoned answer resolves to '+a1.addrs[0])
        elif args.mdns:
            a1 = send_mdns(random_hostname(), args.timeout)
            if a1:
                a2 = send_mdns(random_hostname(), args.timeout)
                if a2:
                    if socket.inet_ntoa(a1.answers[0].rdata) == socket.inet_ntoa(a2.answers[0].rdata):
                        print('[!] Responder detected with mDNS. Poisoned answer resolves to '+str(a1.answers[0]))
    for hostname in  args.hostnames:
        if args.netbios:
            a = send_nbns(hostname, args.netbios, args.timeout, args.qtype, args.qclass, args.service)
            if a and len(a.addrs):
                print('NetBIOS resolved {} to {}'.format(hostname, a.addrs[0]))
        elif args.llmnr:
            a = send_llmnr(hostname, args.timeout, args.qtype, args.qclass)
            if a and len(a.addrs):
                print('LLMNR resolved {} to {}'.format(hostname, a.addrs[0]))
        elif args.mdns:
            a = send_mdns(hostname, args.timeout, args.qtype, args.qclass)
            if a and len(a.answers):
                print('mDNS resolved {} to {}'.format(hostname, str(a.answers[0])))
