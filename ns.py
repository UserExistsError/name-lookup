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
from ctypes import Structure, BigEndianStructure, LittleEndianStructure, c_uint16, c_uint8

'''
Win7 name resolution order: hosts, DNS, LLMNR, NetBIOS

## Conventions
log() -> log single line
logm() -> log multiple lines
to_bytes() -> return object suitable for dumping on the wire

## TODO
1) Each class constructor should take a buffer and attribute params. The object will be initialized
   by the buffer first. Remaining params will override buffer values.
2) Each class will implement to_bytes() and from_bytes()
3) Each class will implement log() and logm() to log single and multi-line strings respectively
4) Test non-default options
5) subclass Record for each type. implement compress()
'''

LLMNR_PORT=5355
LLMNR_GRP='224.0.0.252'         # this is the multicast address reserved for LLMNR
LLMNR6_GRP='ff02::1:3'

MDNS_PORT=5353
MDNS_GRP='224.0.0.251'          # multicast DNS
MDNS6_GRP='ff02::fb'

logger = logging.getLogger(__name__)


class NBNSHeader(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('trans_id', c_uint16),
        # START flags
        ('response', c_uint8, 1), # query or response
        ('opcode', c_uint8, 4),
        ('authoritative', c_uint8, 1), # responding name server is authoritative
        ('truncation', c_uint8, 1), # truncation
        ('recursion_desired', c_uint8, 1), # recursion desired
        ('recursion_available', c_uint8, 1), # recursion available
        ('reserved3', c_uint8, 2),
        ('broadcast', c_uint8, 1),
        ('reserved4', c_uint8, 4),
        # END flags
        ('qdcount', c_uint16),  # query count
        ('ancount', c_uint16),  # answer count
        ('nscount', c_uint16),  # name server count
        ('arcount', c_uint16),  # addtl count
        # followed by resource records
    ]
    def __init__(self, recursion_desired=None):
        if recursion_desired is not None:
            self.recursion_desired = recursion_desired
    def to_bytes(self):
        return bytes(self)
    def logm(self):
        return '''
[NBNS Header]
trans_id 0x{:04x}
response {}
opcode 0x{:01x}
authoritative {}
truncation {}
recursion_desired {}
recursion_available {}
reserved3 {}
broadcast {}
reserved4 {:01x}
qdcount {}
ancount {}
nscount {}
arcount {}
'''.format(self.trans_id, self.response, self.opcode, self.authoritative, self.truncation, self.recursion_desired,
           self.recursion_available, self.reserved3, self.broadcast, self.reserved4, self.qdcount, self.ancount,
           self.nscount, self.arcount)


def decode_netbios_name(e):
    if e[0] == 0x20:
        e = e[1:]
    name = ''
    for i in range(0, len(e), 2):
        v = ((e[i+0]-0x41)<<4) | (e[i+1]-0x41)
        if v == ord(' '): break # break on padding space character
        name += chr(v)
    return name, ((e[-3]-0x41)<<4) | (e[-2]-0x41) # return name and service type

def encode_netbios_name(name, service):
    name += ' ' * (15 - len(name)) # pad with spaces
    name += chr(service)
    nibbles = [(b&0xf, b>>4&0xf) for b in name.encode()]
    e = b'\x20'                    # static length field
    for n in nibbles:
        e += struct.pack('BB', 0x41 + n[1], 0x41 + n[0])
    return e + b'\x00'

class NBNSRecord():
    class TYPE:
        A=0x1
        NS=0x2
        NULL=0xa
        NB=0x20
        NBSTAT=0x21
    class CLASS:
        IN=1
    class SERVICE:
        WORKSTATION=0
        SERVER=0x20
        MASTER_BROWSER=0x1d
        DOMAIN_MASTER_BROWSER=0x1b
    def __init__(self, *, buff=None, name=None, service=None, rtype=None, rclass=None, response=None):
        self.name = ''
        self.service = NBNSRecord.SERVICE.WORKSTATION
        self.rtype = NBNSRecord.TYPE.NB
        self.rclass = NBNSRecord.CLASS.IN
        self.ttl = 60*60
        self.rlen = 0
        self.rdata = b''
        if buff:
            self.from_bytes(buff, response)
        if name is not None:
            self.name = name
        if service is not None:
            self.service = service
        if rtype is not None:
            self.rtype = rtype
        if rclass is not None:
            self.rclass = rclass
    def from_bytes(self, buff, response=None):
        name, rest = buff.split(b'\x00', maxsplit=1)
        self.name, self.service = decode_netbios_name(name)
        self.rtype, self.rclass = struct.unpack('>HH', rest[:4])
        if response is False:
            return self
        rest = rest[4:]
        if response or len(rest) >= 6:
            self.ttl, self.rlen = struct.unpack('>LH',rest[:6])
            if len(rest[6:]) >= self.rlen:
                self.rdata = rest[6:6+self.rlen]
            elif response:
                raise ValueError('Not enough data for Record')
            else:
                # oops. not enough rdata. must not be a response
                self.ttl = 60*60
                self.rlen = 0
                self.rdata = ''
        return self
    def to_bytes(self):
        buff = encode_netbios_name(self.name, self.service)
        buff += struct.pack('>HH', self.rtype, self.rclass)
        self.rlen = len(self.rdata)
        if self.rlen:
            # RR is a response
            buff += struct.pack('>LH', self.ttl, self.rlen)
            buff += self.rdata
        return buff
    def __len__(self):
        return len(self.to_bytes())
    def value(self):
        if self.rtype == NBNSRecord.TYPE.NB:
            flags = struct.unpack('>H', self.rdata[:2])[0]
            return socket.inet_ntoa(self.rdata[2:6])
        raise NotImplementedError('NBNSRecord type={} class={}'.format(self.rtype, self.rclass))
    def __str__(self):
        return self.value()
    def logm(self):
        return '''
[NBNSRecord]
name   {}
service 0x{:02x}
rtype   0x{:04x}
rclass  0x{:04x}
'''.format(self.name, self.service, self.rtype, self.rclass)

class NBNS():
    ''' https://www.ietf.org/rfc/rfc1002.txt '''
    def __init__(self, *, buff=None, header=None, queries=None, answers=None, authorities=None, additionals=None):
        self.header = NBNSHeader()
        self.queries = []
        self.answers = []
        self.authorities = []
        self.additionals = []
        if buff:
            self.from_bytes(buff)
        if header is not None:
            self.header = header
        if queries is not None:
            self.queries = queries
        if answers is not None:
            self.answers = answers
        if authorities is not None:
            self.authorities = authorities
        if additionals is not None:
            self.additionals = additionals
    def from_bytes(self, buff):
        self.header = NBNSHeader.from_buffer_copy(buff[:12])
        buff = buff[12:]
        for i in range(self.header.qdcount):
            rr = NBNSRecord(buff=buff, response=self.header.response)
            self.queries.append(rr)
            buff = buff[len(rr):]
        for i in range(self.header.ancount):
            rr = NBNSRecord(buff=buff, response=self.header.response)
            self.answers.append(rr)
            buff = buff[len(rr):]
        for i in range(self.header.nscount):
            rr = NBNSRecord(buff=buff, response=self.header.response)
            self.authorities.append(rr)
            buff = buff[len(rr):]
        for i in range(self.header.arcount):
            rr = NBNSRecord(buff=buff, response=self.header.response)
            self.additionals.append(rr)
            buff = buff[len(rer):]
        return self
    def to_bytes(self):
        buff = b''
        self.header.qdcount = len(self.queries)
        for rr in self.queries:
            buff += rr.to_bytes()
        self.header.ancount = len(self.answers)
        for rr in self.answers:
            buff += rr.to_bytes()
        self.header.nscount = len(self.authorities)
        for rr in self.authorities:
            buff += rr.to_bytes()
        self.header.arcount = len(self.additionals)
        for rr in self.additionals:
            buff += rr.to_bytes()
        return self.header.to_bytes() + buff
    def logm(self):
        s = self.header.logm()
        for records in [self.queries, self.answers, self.authorities, self.additionals]:
            for r in records:
                s += r.logm()
        return s


class NBNSRequest(NBNS):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if kwargs.get('buff', True) and kwargs.get('header', True):
            self.header.response = 0
            self.header.trans_id = random.randint(1, 0xfffe)
            self.header.broadcast = 1


class NBNSResponse(NBNS):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if kwargs.get('buff', True) and kwargs.get('header', True):
            self.header.response = 1

class DNSHeader(BigEndianStructure):
    _pack_ = 1
    _fields_ = [
        ('trans_id', c_uint16),
        # START flags
        ('response', c_uint16, 1), # query or response
        ('opcode', c_uint16, 4),
        ('authoritative', c_uint16, 1), # responding name server is authoritative
        ('truncation', c_uint16, 1), # truncation
        ('recursion_desired', c_uint16, 1), # recursion desired
        ('recursion_available', c_uint16, 1), # recursion available
        ('reserved', c_uint16, 2),
        ('auth', c_uint16, 1),  # non-auth buff acceptable
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
    def logm(self):
        return '''
[DNS Header]
trans_id 0x{:04x}
response {}
opcode 0x{:01x}
authoritative {}
truncation {}
recursion_desired {}
recursion_available {}
reserved {}
auth {}
rcode 0x{:01x}
qdcount {}
ancount {}
nscount {}
arcount {}
'''.format(self.trans_id, self.response, self.opcode, self.authoritative, self.truncation,
           self.recursion_desired, self.recursion_available, self.reserved,
           self.auth, self.rcode, self.qdcount, self.ancount, self.nscount, self.arcount)


class DNS():
    pass

class DNSRequest(DNS):
    pass

class DNSReponse(DNS):
    pass

def encode_dns_name(name, end=b'\x00'):
    ''' encode DNS name. end should be 0x00 or 16 bit precomputed compression offset '''
    name = name.rstrip('.')
    name = name.strip('.')
    e = b''
    for n in name.split('.'):
        e += int.to_bytes(len(n), 1, byteorder='big') + n.encode()
    return e + end

def decode_dns_name(e, pkt):
    ''' e is the encoded name. pkt is entire DNS packet and is required for decompression '''
    if e[0] == 0:
        return ''
    if e[0] >= 0xc0:            # compression offset
        offset = struct.unpack('>H', e[:2])[0] & 0x3fff
        return decode_dns_name(pkt[offset:], pkt)
    elif e[0] > 63:             # max label length
        raise ValueError('Unexpected label prefix: 0x{:02x}'.format(e[0]))
    part = decode_dns_name(e[1+e[0]:], pkt)
    if len(part):
        return e[1:1+e[0]].decode() + '.' + part
    return e[1:1+e[0]].decode()


class DNSCompressCtx():
    ''' compression context. pass to DNSCompressable.compress() '''
    def __init__(self):
        self.offsets = {}
        self.buff = b'\xff' * 12     # dummy query/record header
    def to_bytes(self):
        return self.buff[12:]
    def __contains__(self, obj):
        return obj in self.offsets
    def add_offset(self, data, o):
        if data not in self.offsets:
            self.offsets[data] = len(self.buff) + o
    def add(self, data):
        ''' append data to buffer '''
        self.buff += data

class DNSCompressable():
    ''' class to provide DNS compression of names. use only as a base class. '''
    def compress_single(self, data, ctx):
        data = b'.' + data      # makes first label a compress target
        for i in range(len(data)):
            if data[i:] in ctx:
                off = struct.pack('>H', ctx.offsets[data[i:]] | 0xc000)
                left = data[:i]
                for o in range(len(left)):
                    if data[o:o+1] != b'.': continue # only domain labels are compress targets
                    ctx.add_offset(data[o:], o)
                return ctx.add(encode_dns_name(left.decode(), off))
        for o in range(len(data)):
            if data[o:o+1] != b'.': continue
            ctx.add_offset(data[o:], o)
        return ctx.add(encode_dns_name(data.decode()))
    def compress(self, ctx):
        ''' default is to compress name only. each subclass should implement this for rdata '''
        self.compress_single(self.name.encode(), ctx)
        ctx.add(self.header_bytes())


class DNSQuery(DNSCompressable):
    def __init__(self, buff=None, pkt=None, name=None, rtype=None, rclass=None):
        self.name = ''
        self.rtype = DNSRecord.TYPE.A
        self.rclass = DNSRecord.CLASS.IN
        if buff:
            self.from_bytes(buff, pkt)
        if name is not None:
            self.name = name
        if rtype is not None:
            self.rtype = rtype
        if rclass is not None:
            self.rclass = rclass
    def from_bytes(self, buff, pkt=None):
        self.name = decode_dns_name(buff, pkt)
        buff = buff[buff.find(b'\x00')+1:]
        self.rtype, self.rclass = struct.unpack('>HH', buff[:4])
        return self
    def __len__(self):
        return len(self.to_bytes())
    def header_bytes(self):
        return struct.pack('>HH', self.rtype, self.rclass)
    def to_bytes(self):
        return encode_dns_name(self.name) + self.header_bytes()
    def value(self):
        return self.name
    def __str__(self):
        return self.value()
    def log(self):
        return '[DNSQuery] (name={}) (type={}) (class={})'.format(self.name, self.rtype, self.rclass)
    def logm(self):
        return '''
[DNSQuery]
name {}
type {}
class {}
'''.format(self.name, self.rtype, self.rclass)

class DNSRecord(DNSCompressable):
    ''' https://www.ietf.org/rfc/rfc1035.txt '''
    class TYPE:
        A=1
        CNAME=5
        SOA=6
        PTR=12
        AAAA=28
    class CLASS:
        IN=1

    @staticmethod
    def convert_type_str(t):
        return {
            'A':DNSRecord.TYPE.A, 'AAAA':DNSRecord.TYPE.AAAA
        }.get(t.upper(), None)

    def __init__(self, *, buff=None, pkt=None, name=None, rtype=None, rclass=None, ttl=None, rdata=None):
        self.name = ''
        self.rtype = DNSRecord.TYPE.A
        self.rclass = DNSRecord.CLASS.IN
        self.ttl = 60*60        # 1 hour
        self.rlen = 0           # rdata length
        self.rdata = b''
        if buff:
            self.from_bytes(buff, pkt)
        if name is not None:
            self.name = name
        if rtype is not None:
            self.rtype = rtype
        if rclass is not None:
            self.rclass = rclass
        if ttl is not None:
            self.ttl = ttl
        if rdata is not None:
            self.rdata = rdata
            self.rlen = len(data)
    def from_bytes(self, buff, pkt):
        self.name = decode_dns_name(buff, pkt)
        buff = buff[buff.find(b'\x00')+1:]
        self.rtype, self.rclass = struct.unpack('>HH', buff[:4])
        buff = buff[4:]
        self.ttl, self.rlen = struct.unpack('>LH', buff[:6])
        if len(buff[6:]) >= self.rlen:
            self.rdata = buff[6:6+self.rlen]
        else:
            raise ValueError('Not enough data for Record')
    def __len__(self):
        return len(self.to_bytes())
    def header_bytes(self):
        return struct.pack('>HHLH', self.rtype, self.rclass, self.ttl, self.rlen)
    def to_bytes(self):
        self.rlen = len(self.rdata)
        return encode_dns_name(self.name) + self.header_bytes() + self.rdata
    def value(self):
        # XXX implement this for each subclass
        if self.rtype == DNSRecord.TYPE.A:
            return socket.inet_ntop(socket.AF_INET, self.rdata)
        elif self.rtype == DNSRecord.TYPE.AAAA:
            return socket.inet_ntop(socket.AF_INET6, self.rdata)
        elif self.rtype == DNSRecord.TYPE.CNAME:
            return decode_dns_name(self.rdata)
        elif self.rtype == DNSRecord.TYPE.SOA:
            pass
        elif self.rtype == DNSRecord.TYPE.PTR:
            pass
        raise NotImplementedError(self.log())
    def __str__(self):
        return self.value()
    def log(self):
        return '[DNSRecord] (name={}) (type={}) (rclass={}) (ttl={}) (rlen={})'.format(
            self.name, self.rtype, self.rclass, self.ttl, self.rlen)
    def logm(self):
        return '''
[DNSRecord]
name {}
type {}
class {}
ttl {}
rlen {}
'''.format(self.name, self.rtype, self.rclass, self.ttl, self.rlen)


class DNSRecordA(DNSRecord):
    def __init__(self, *, address=None, **kwargs):
        kwargs['rtype'] = DNSRecord.TYPE.A
        super().__init__(**kwargs)
        if address is not None:
            self.address = address
        elif len(self.rdata) > 0:
            self.address = socket.inet_ntop(socket.AF_INET, self.rdata)
    def to_bytes(self):
        self.rdata = socket.inet_pton(socket.AF_INET, self.address)
        return super().to_bytes()
    def compress(self, ctx):
        self.rdata = socket.inet_pton(socket.AF_INET, self.address)
        super().compress(ctx)
    def __str__(self):
        return socket.inet_ntop(socket.AF_INET, self.rdata)

class DNSRecordAAAA(DNSRecord):
    def __init__(self, *, address=None, **kwargs):
        kwargs['rtype'] = DNSRecord.TYPE.AAAA
        super().__init__(**kwargs)
        if address is not None:
            self.address = address
        elif len(self.rdata) > 0:
            self.address = socket.inet_ntop(socket.AF_INET6, self.rdata)
    def to_bytes(self):
        self.rdata = socket.inet_pton(socket.AF_INET6, self.address)
        return super().to_bytes()
    def __str__(self):
        return socket.inet_ntop(socket.AF_INET6, self.rdata)

class DNSRecordNS(DNSRecord):
    def __init__(self, *, name_server=None, **kwargs):
        kwargs['rtype'] = DNSRecord.TYPE.NS
        super().__init__(**kwargs)
        if name_server is not None:
            self.name_server = name_server
        elif len(self.rdata) > 0:
            self.name_server = decode_dns_name()

class DNSRecordCNAME(DNSRecord):
    def __init__(self, *, cname=None, **kwargs):
        kwargs['rtype'] = DNSRecord.TYPE.CNAME
        super().__init__(**kwargs)
        if cname is not None:
            self.cname = cname
        elif len(self.rdata) > 0:
            self.cname = decode_dns_name(self.rdata, kwargs.get('pkt', None))
    def to_bytes(self):
        self.rdata = self.compress(self.cname, buff)

class DNSRecordSOA(DNSRecord):
    def __init__(self, *, name_server=None, mailbox=None, serial=None, refresh=None, retry=None,
                 expires=None, min_ttl=None, **kwargs):
        super().__init__(DNSRecord.TYPE.SOA, **kwargs)
        pass


class MDNSHeader(DNSHeader):
    ''' NOTE: trans_id should be zero for multicast responses 
    https://tools.ietf.org/html/rfc6762#section-18.1 '''
    pass

class MDNSQuery(DNSQuery):
    def __init__(self, *, buff=None, pkt=None, name=None, rtype=None, rclass=None, unicast_reply=None):
        super().__init__(buff=buff, pkt=pkt, name=name, rtype=rtype, rclass=rclass)
        self.rclass = self.rclass & 0x7fff
        if unicast_reply is not None:
            self.unicast_reply = unicast_reply
        else:
            self.unicast_reply = self.rclass >> 15
    def from_bytes(self, buff, pkt):
        super().from_bytes(buff, pkt)
        self.unicast_reply = self.rclass >> 15
        self.rclass = self.rclass & 0x7fff
    def to_bytes(self):
        self.rclass = (self.unicast_reply << 15) | (self.rclass & 0x7fff)
        buff = super().to_bytes()
        self.rclass = self.rclass & 0x7fff
        return buff

class MDNSRecord(DNSRecord):
    def __init__(self, *, cache_flush=None, **kwargs):
        self.cache_flush = 0
        super().__init__(**kwargs)
        self._unpack_cache_flush()
        if cache_flush is not None:
            self.cache_flush = cache_flush
    def from_bytes(self, buff, pkt):
        super().from_bytes(buff, pkt)
        self._unpack_cache_flush()
    def to_bytes(self):
        self._pack_cache_flush()
        buff = super().to_bytes()
        self.rclass = self.rclass & 0x7fff
        return buff
    def _unpack_cache_flush(self):
        ''' unpack rclass to get cache_flush '''
        self.cache_flush = self.rclass >> 15
        self.rclass = self.rclass & 0x7fff
    def _pack_cache_flush(self):
        ''' pack cache_flush into rclass so DNSRecord.to_bytes() can be used '''
        self.rclass = (self.cache_flush << 15) | (self.rclass & 0x7fff)

class MDNSRecordA(MDNSRecord, DNSRecordA):
    def __init__(self, *, cache_flush=None, **kwargs):
        DNSRecordA.__init__(self, **kwargs)
        self._unpack_cache_flush()
        if cache_flush is not None:
            self.cache_flush = cache_flush


class MDNS():
    ''' mDNS packet class '''
    Query=MDNSQuery
    Record=MDNSRecord
    Header=MDNSHeader
    record_map = {
        DNSRecord.TYPE.A:MDNSRecordA,
        #DNSRecord.TYPE.A:MDNSRecordAAAA,
    }
    def __init__(self, *, buff=None, header=None, queries=None, answers=None, authorities=None, additionals=None):
        self.header = self.Header()
        self.queries = []
        self.answers = []
        self.authorities = []
        self.additionals = []
        if buff:
            self.from_bytes(buff)
        if header is not None:
            self.header = self.Header()
        if queries is not None:
            self.queries = queries
        if answers is not None:
            self.answers = answers
        if authorities is not None:
            self.authorities = authorities
        if additionals is not None:
            self.additionals = additionals
    def from_bytes(self, buff):
        self.header = self.Header.from_buffer_copy(buff[:12])
        buff = buff[12:]
        for i in range(self.header.qdcount):
            rr = self.Query(buff=buff)
            self.queries.append(rr)
            buff = buff[len(rr):]
        for i in range(self.header.ancount):
            rr = self.Record(buff=buff)
            rr = self.record_map[rr.rtype](buff=buff)
            self.answers.append(rr)
            buff = buff[len(rr):]
        for i in range(self.header.nscount):
            rr = self.Record(buff=buff)
            self.authorities.append(rr)
            buff = buff[len(rr):]
        for i in range(self.header.arcount):
            rr = self.Record(buff=buff)
            self.additionals.append(rr)
            buff = buff[len(rr):]
        return self
    def compress_data(self):
        ctx = DNSCompressCtx()
        for q in self.queries:
            q.compress(ctx)
        for records in [self.answers, self.authorities, self.additionals]:
            for r in records:
                r.compress(ctx)
        return ctx.to_bytes()
    def to_bytes(self, compress=True):
        self.header.qdcount = len(self.queries)
        self.header.ancount = len(self.answers)
        self.header.nscount = len(self.authorities)
        self.header.arcount = len(self.additionals)
        if compress:
            buff = self.compress_data()
        else:
            buff = b''
            for records in [self.queries, self.answers, self.authorities, self.additionals]:
                for r in records:
                    buff += r.to_bytes()
        return self.header.to_bytes() + buff
    def log(self):
        s = self.header.log() + linesep
        for records in [self.queries, self.answers, self.authorities, self.additionals]:
            for r in records:
                s += r.log() + linesep
        return s[:-len(linesep)]
    def logm(self):
        s = self.header.logm()
        for records in [self.queries, self.answers, self.authorities, self.additionals]:
            for r in records:
                s += r.logm()
        return s


class MDNSRequest(MDNS):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if kwargs.get('buff', True) and kwargs.get('header', True):
            self.header.response = 0
            self.header.trans_id = random.randint(1, 0xfffe)


class MDNSResponse(MDNS):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if kwargs.get('buff', True) and kwargs.get('header', True):
            self.header.response = 1


class LLMNRQuery(DNSQuery):
    pass

class LLMNRRecord(DNSRecord):
    pass

class LLMNRHeader(BigEndianStructure):
    ''' https://www.ietf.org/rfc/rfc4795.txt '''
    _pack_ = 1
    _fields_ = [
        ('trans_id', c_uint16),
        # START flags
        ('response', c_uint16, 1), # query or response
        ('opcode', c_uint16, 4),
        ('conflict', c_uint16, 1),
        ('truncation', c_uint16, 1), # truncation
        ('tentative', c_uint16, 1),
        ('reserved', c_uint16, 4),
        ('rcode', c_uint16, 4),
        # END flags
        ('qdcount', c_uint16),  # query count
        ('ancount', c_uint16),  # answer count
        ('nscount', c_uint16),  # name server count
        ('arcount', c_uint16),  # addtl count
        # followed by resource records
    ]
    def to_bytes(self):
        return bytes(self)
    def logm(self):
        return '''
[LLMNR Header]
trans_id 0x{:04x}
response {}
opcode 0x{:01x}
conflict {}
truncation {}
tentative {}
reserved 0x{:01x}
rcode 0x{:01x}
qdcount {}
ancount {}
nscount {}
arcount {}
'''.format(self.trans_id, self.response, self.opcode, self.conflict, self.truncation,
           self.tentative, self.reserved, self.rcode,
           self.qdcount, self.ancount, self.nscount, self.arcount)


class LLMNR(MDNS):
    Header=LLMNRHeader
    Record=LLMNRRecord

class LLMNRRequest(LLMNR):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if kwargs.get('buff', True) and kwargs.get('header', True):
            self.header.response = 0
            self.header.trans_id = random.randint(1, 0xfffe)


class LLMNRResponse(LLMNR):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if kwargs.get('buff', True) and kwargs.get('header', True):
            self.header.response = 1

def random_hostname(length=15):
    return random.choice(string.ascii_letters) + \
        ''.join([random.choice(string.ascii_letters+string.digits+'--') for i in range(14)])


def send_mdns(args, hostname):
    q = MDNSRequest(queries=[MDNSQuery(name=hostname, rtype=args.rtype)])
    if args.ip4:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        s.sendto(q.to_bytes(), (MDNS_GRP, MDNS_PORT))
        r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        r.bind(('', MDNS_PORT))
        r.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, struct.pack('=4sl', socket.inet_aton(MDNS_GRP), socket.INADDR_ANY))
    else:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IP_MULTICAST_TTL, 1)
        s.sendto(q.to_bytes(), (MDNS6_GRP, MDNS_PORT))
        r = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        r.bind(('', MDNS_PORT))
        r.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                     struct.pack('=16sl', socket.inet_pton(socket.AF_INET6, MDNS6_GRP), socket.INADDR_ANY))
    logger.debug('mDNS Query "{}", TransID 0x{:04x}'.format(hostname, q.header.trans_id))
    if r in select.select([r], [], [], args.timeout)[0]:
        buff, addr = r.recvfrom(4096)
        a = MDNSResponse(buff=buff)
        logger.debug('mDNS Response from {}, TransId 0x{:04x}, Answer {}'.format(addr[0], a.header.trans_id, a.answers[0].value()))
        return a
    return None

def send_llmnr(args, hostname):
    q = LLMNRRequest(queries=[LLMNRQuery(name=hostname, rtype=args.rtype)])
    if args.ip4:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        s.sendto(q.to_bytes(), (LLMNR_GRP, LLMNR_PORT))
    else:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IP_MULTICAST_TTL, 1)
        s.sendto(q.to_bytes(), (MDNS6_GRP, MDNS_PORT))
    logger.debug('LLMNR Query "{}", TransID 0x{:04x}'.format(hostname, q.header.trans_id))
    if s in select.select([s], [], [], args.timeout)[0]:
        buff, addr = s.recvfrom(4096)
        a = LLMNRResponse(buff=buff)
        logger.debug('LLMNR Response from {}, TransId 0x{:04x}, Answer {}'.format(addr[0], a.header.trans_id, a.answers[0]))
        if a.header.trans_id == q.header.trans_id:
            return a
    return None


def send_nbns(args, hostname):
    q = NBNSRequest(queries=[NBNSRecord(name=hostname, service=args.service)], header=NBNSHeader(recursion_desired=1))
    if args.ip4:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        bcast = get_bcast_addr(args.netbios)
        s.sendto(q.to_bytes(), (bcast, 137))
    else:
        print_warn('NBNS does not support IPv6')
        sys.exit()
    logger.debug('NBNS Query "{}", TransID 0x{:04x}, bcast {}'.format(hostname, q.header.trans_id, bcast))
    if s in select.select([s], [], [], args.timeout)[0]:
        buff, addr = s.recvfrom(1024)
        r = NBNSResponse(buff=buff)
        logger.debug('NBNS Response from {}, TransId 0x{:04x}, Answer {}'.format(addr[0], r.header.trans_id, r.answers[0].value()))
        if r.header.trans_id == q.header.trans_id:
            return r
    return None

def get_bcast_addr(interface):
    try:
        # check if we have an IP already
        socket.inet_pton(socket.AF_INET, interface)
        return interface
    except Exception:
        pass
    for line in open('/proc/net/route'):
        iface, dest, gw, flags, refcnt, use, metric, mask = line.split()[:8]
        if iface == interface and gw == '00000000' and dest != '0000FEA9':
            net = int(dest, 16)
            host = net | ((2**32-1)-int(mask, 16))
            return socket.inet_ntop(socket.AF_INET, (net | host).to_bytes(4, byteorder='little'))
    raise RuntimeError('failed to find broadcast address for interface')


def print_color(c, s):
    if sys.platform.lower().startswith('linux'):
        print(c+'\u001b[0m'+s)
    else:
        print(s)

def print_good(s):
    print_color('\u001b[32m[+] ', s)

def print_bad(s):
    print_color('\u001b[31m[-] ', s)

def print_warn(s):
    print_color('\u001b[33;1m[!] ', s)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--responder', action='store_true', help='detect responder')
    parser.add_argument('-t', '--timeout', type=int, default=1, help='response timeout. default 1')
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug output')
    parser.add_argument('--type', dest='rtype', type=str.upper, choices=['A', 'AAAA'], default='A',
                        help='query type. defaults LLMNR/mDNS => A, NetBIOS => NB')
    parser.add_argument('hostnames', nargs='*', help='hostnames to resolve')
    parser.add_argument('--service', type=lambda x:int(x, 16), default=NBNSRecord.SERVICE.WORKSTATION,
                        help='NetBIOS service type. default is 0x00 (Workstation)')
    parser.add_argument('--service-types', dest='srvtypes', action='store_true',
                        help='List all NetBIOS service types and exit')
    family = parser.add_mutually_exclusive_group()
    family.add_argument('-4', dest='ip4', action='store_true', help='use IPv4. default')
    family.add_argument('-6', dest='ip6', action='store_true', help='use IPv6')
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

    args.rtype = DNSRecord.convert_type_str(args.rtype)

    if not args.ip6:
        args.ip4 = True

    if args.responder:
        if args.netbios:
            a1 = send_nbns(args, random_hostname())
            if a1:
                a2 = send_nbns(args, random_hostname())
                if a2:
                    if a1.answers[0].value() == a2.answers[0].value():
                        print_warn('NBNS Responder detected. Poisoned answer resolves to '+str(a1.answers[0]))
        elif args.llmnr:
            a1 = send_llmnr(args, random_hostname())
            if a1:
                a2 = send_llmnr(args, random_hostname())
                if a2:
                    if a1.answers[0].value() == a2.answers[0].value():
                        print_warn('LLMNR Responder detected. Poisoned answer resolves to '+a1.answers[0].value())
        elif args.mdns:
            a1 = send_mdns(args, random_hostname())
            if a1:
                a2 = send_mdns(args, random_hostname())
                if a2:
                    if a1.answers[0].value() == a2.answers[0].value():
                        print_warn('mDNS Responder detected. Poisoned answer resolves to '+str(a1.answers[0]))
    for hostname in args.hostnames:
        if args.netbios:
            a = send_nbns(args, hostname)
            if a and len(a.answers):
                print_good('NBNS resolved {} to {}'.format(hostname, a.answers[0]))
        elif args.llmnr:
            a = send_llmnr(args, hostname)
            if a and len(a.answers):
                print_good('LLMNR resolved {} to {}'.format(hostname, a.answers[0]))
        elif args.mdns:
            a = send_mdns(args, hostname)
            if a and len(a.answers):
                print_good('mDNS resolved {} to {}'.format(hostname, a.answers[0]))
