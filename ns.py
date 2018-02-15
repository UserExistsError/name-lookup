#!/usr/bin/env python3
import sys
import socket
import random
import struct
import select
import string
import logging
import argparse
from ctypes import Structure, BigEndianStructure, LittleEndianStructure, c_uint16

'''
Win7 name resolution order: hosts, DNS, LLMNR, NetBIOS
'''

LLMNR_PORT=5355
LLMNR_GRP='224.0.0.252'         # this is the multicast address reserved for LLMNR

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

class DNSFlags(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('response', c_uint16, 1),
        ('opcode', c_uint16, 4),
        ('reserved', c_uint16, 1),
        ('truncated', c_uint16, 1),
        ('recursion', c_uint16, 1),
        ('reserved1', c_uint16, 3),
        ('noauth', c_uint16, 1),
        ('reserved2', c_uint16, 4),
    ]

def decode_dns_name(self, e):
    name = ''
    i = 0
    while e[i]:
        name += e[i+1:e[i]+1] + '.'
        i = e[e[i]+2]
    return name[:-1]

class ResourceRecord():
    def __init__(self, packet, data):
        self.name, self._type, self._class, self.ttl, self.dlen = struct.unpack('>HHHLH', data)
        self.data = data[12:12+self.dlen]
        if self.name[0] == 0xc0:
            # C0 can come after a CN too
            self.name = decode_dns_name(packet[self.name[1]:])
    def __len__(self):
        return 12 + self.dlen

class DNSResponse():
    def __init__(self):
        pass
    def from_data(self, data):
        self.trans_id = struct.unpack('>H', data[0:2])[0]
        self.flags = DNSFlags.from_buffer_copy(data[2:4])
        self.query_count, self.answer_count, self.authority_count, self.additional_count = \
            struct.unpack('>HHHH', data[4:12])
        queries = data[12:]
        for i in range(self.query_count):
            name = decode_dns_name(queries)
            typ, clas = struct.unpack('>HH', queries[len(name)+1:len(name)+5])
            queries = queries[len(name)+5:]
        answers = queries
        self.answers = []
        for i in range(self.answer_count):
            rr = ResourceRecord(answers)
            self.answers.append(rr)
            answers = answers[len(rr):]
        authorities = answers
        self.authorities = []
        for i in range(self.authority_count):
            rr = ResourceRecord(authorities)
            self.authorities.append(rr)
            authorities = authorities[len(rr):]
        additionals = authorities
        self.additionals = []
        for i in range(self.additionals):
            rr = ResourceRecord(additionals)
            self.additionals.append(rr)
            additionals = additionals[len(rr):]

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


class MDNSQuery():
    pass

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
    parser.add_argument('hostname', nargs='?', help='hostname to resolve')
    parser.add_argument('--service', type=lambda x:int(x, 16), default=0x00,
                        help='NetBIOS service type. default is 0x00 (Workstation)')
    parser.add_argument('--service-types', dest='srvtypes', action='store_true',
                        help='List all NetBIOS service types and exit')
    proto = parser.add_mutually_exclusive_group()
    proto.add_argument('--llmnr', action='store_true', help='use LLMNR. default')
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
    if not any([args.llmnr, args.netbios]):
        args.llmnr = True
    if not args.hostname and not args.responder:
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
                        print('[!] Responder detected with NetBIOS')
        elif args.llmnr:
            a1 = send_llmnr(random_hostname(), args.timeout)
            if a1:
                a2 = send_llmnr(random_hostname(), args.timeout)
                if a2:
                    if a1.addrs[0] == a2.addrs[0]:
                        print('[!] Responder detected with LLMNR')
    if args.hostname:
        if args.netbios:
            a = send_nbns(args.hostname, args.netbios, args.timeout, args.qtype, args.qclass, args.service)
            if a and len(a.addrs):
                print('NetBIOS resolved {} to {}'.format(args.hostname, a.addrs[0]))
        elif args.llmnr:
            a = send_llmnr(args.hostname, args.timeout, args.qtype, args.qclass)
            if a and len(a.addrs):
                print('LLMNR resolved {} to {}'.format(args.hostname, a.addrs[0]))
