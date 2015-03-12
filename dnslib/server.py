# -*- coding: utf-8 -*-

"""
    DNS server framework - intended to simplify creation of custom resolvers.

    Comprises the following components:

        DNSServer   - socketserver wrapper (in most cases you should just
                      need to pass this an appropriate resolver instance
                      and start in either foreground/background)

        DNSHandler  - handler instantiated by DNSServer to handle requests
                      The 'handle' method deals with the sending/receiving
                      packets (handling TCP length prefix) and delegates
                      the protocol handling to 'get_reply'. This decodes
                      packet, hands off a DNSRecord to the Resolver instance, 
                      and encodes the returned DNSRecord. 
                      
                      In most cases you dont need to change DNSHandler unless
                      you need to get hold of the raw protocol data in the
                      Resolver

        DNSLogger   - The class provides a default set of logging functions for
                      the various stages of the request handled by a DNSServer
                      instance which are enabled/disabled by flags in the 'log'
                      class variable. 

        Resolver    - Instance implementing a 'resolve' method that receives 
                      the decodes request packet and returns a response. 
                        
                      To implement a custom resolver in most cases all you need
                      is to implement this interface.

                      Note that there is only a single instance of the Resolver
                      so need to be careful about thread-safety and blocking

        The following examples use the server framework:

            fixedresolver.py    - Simple resolver which will respond to all
                                  requests with a fixed response
            zoneresolver.py     - Resolver which will take a standard zone
                                  file input
            shellresolver.py    - Example of a dynamic resolver
            proxy.py            - DNS proxy
            intercept.py        - Intercepting DNS proxy

        >>> resolver = BaseResolver()
        >>> logger = DNSLogger(prefix=False)
        >>> server = DNSServer(resolver,port=8053,address="localhost",logger=logger)
        >>> server.start_thread()
        >>> q = DNSRecord.question("abc.def")
        >>> a = q.send("localhost",8053)
        Request: [...] (udp) / 'abc.def.' (A)
        Reply: [...] (udp) / 'abc.def.' (A) / RRs: 
        >>> print(DNSRecord.parse(a))
        ;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: ...
        ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;abc.def.                       IN      A
        >>> server.stop()

        >>> class TestResolver:
        ...     def resolve(self,request,handler):
        ...         reply = request.reply()
        ...         reply.add_answer(*RR.fromZone("abc.def. 60 A 1.2.3.4"))
        ...         return reply
        >>> resolver = TestResolver()
        >>> server = DNSServer(resolver,port=8053,address="localhost",logger=logger,tcp=True)
        >>> server.start_thread()
        >>> a = q.send("localhost",8053,tcp=True)
        Request: [...] (tcp) / 'abc.def.' (A)
        Reply: [...] (tcp) / 'abc.def.' (A) / RRs: A
        >>> print(DNSRecord.parse(a))
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
        ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;abc.def.                       IN      A
        ;; ANSWER SECTION:
        abc.def.                60      IN      A       1.2.3.4
        >>> server.stop()


"""
from __future__ import print_function

import binascii,time
from lib.crypto import nacl
from dns.dnscurve_operations import dnscurve_decode_streamlined
from infrastructure.scion_elem import SCIONElement
from lib.packet.scion import SCIONPacket, PacketType as PT,\
    SCIONHeader, get_type, PacketType
from lib.packet.host_addr import IPv4HostAddr
from lib.packet.path import EmptyPath


try:
    import socketserver
except ImportError:
    import SocketServer as socketserver

from dnslib import DNSRecord, DNSError, QTYPE

class DNSPacket(SCIONPacket):
    """
    The SCION DNS packet.
    """
    def __init__(self, raw=None):
        SCIONPacket.__init__(self)

    def parse(self, raw):
        SCIONPacket.parse(self, raw)

    @classmethod
    def from_values(cls, dst):
        """
        Returns a DNS packet with the specified values.

        @param dst: Destination address (must be a 'HostAddr' object)
        """
        dns_packet = DNSPacket()
        src = ""

        #TODO: src = get_addr_from_type(PacketType.DNS_QUERY)
        dns_packet.hdr = SCIONHeader.from_values(src, dst, PacketType.DATA)
        return dns_packet

class BaseResolver(object):
    """
        Base resolver implementation. Provides 'resolve' method which is
        called by DNSHandler with the decode request (DNSRecord instance) 
        and returns a DNSRecord instance as reply.

        In most cases you should be able to create a custom resolver by
        just replacing the resolve method with appropriate resolver code for
        application (see fixedresolver/zoneresolver/shellresolver for
        examples)

        Note that a single instance is used by all DNSHandler instances so 
        need to consider blocking & thread safety.
    """
    def resolve(self, request, handler, sd = None):
        """
            Routine to resolve dns queries. The subclasses need
            to override this method to provide their functionalities.
        """
        pass

class DNSLogger:

    """
        The class provides a default set of logging functions for the various
        stages of the request handled by a DNSServer instance which are
        enabled/disabled by flags in the 'log' class variable.

        To customise logging create an object which implements the DNSLogger
        interface and pass instance to DNSServer.

        The methods which the logger instance must implement are:

            log_recv          - Raw packet received
            log_send          - Raw packet sent
            log_request       - DNS Request
            log_reply         - DNS Response
            log_truncated     - Truncated
            log_error         - Decoding error
            log_data          - Dump full request/response
    """

    def __init__(self, log="", prefix=True):
        """
            Selectively enable log hooks depending on log argument
            (comma separated list of hooks to enable/disable)

            - If empty enable default log hooks
            - If entry starts with '+' (eg. +send,+recv) enable hook
            - If entry starts with '-' (eg. -data) disable hook
            - If entry doesn't start with +/- replace defaults

            Prefix argument enables/disables log prefix
        """
        default = ["request", "reply", "truncated", "error"]
        log = log.split(",") if log else []
        enabled = set([ s for s in log if s[0] not in '+-'] or default)
        [ enabled.add(l[1:]) for l in log if l.startswith('+') ]
        [ enabled.discard(l[1:]) for l in log if l.startswith('-') ]
        for l in ['log_recv', 'log_send', 'log_request', 'log_reply',
                  'log_truncated', 'log_error', 'log_data']:
            if l[4:] not in enabled:
                setattr(self, l, self.log_pass)
        self.prefix = prefix

    def log_pass(self, *args):
        pass

    def log_prefix(self, handler):
        if self.prefix:
            return "%s [%s:%s] " % (time.strftime("%Y-%M-%d %X"),
                               handler.__class__.__name__,
                               handler.server.resolver.__class__.__name__)
        else:
            return ""

    def log_recv(self, handler, data):
        print("%sReceived: [%s:%d] (%s) <%d> : %s" % (
                    self.log_prefix(handler),
                    handler.client_address[0],
                    handler.client_address[1],
                    handler.protocol,
                    len(data),
                    binascii.hexlify(data)))

    def log_send(self, handler, data):
        print("%sSent: [%s:%d] (%s) <%d> : %s" % (
                    self.log_prefix(handler),
                    handler.client_address[0],
                    handler.client_address[1],
                    handler.protocol,
                    len(data),
                    binascii.hexlify(data)))

    def log_request(self, handler, request):

        print("%sRequest: [%s:%d] (%s) / '%s' (%s)" % (
                    self.log_prefix(handler),
                    handler.client_address[0],
                    handler.client_address[1],
                    handler.protocol,
                    request.q.qname,
                    QTYPE[request.q.qtype]))
        self.log_data(request)

    def log_reply(self, handler, reply):
        print("%sReply: [%s:%d] (%s) / '%s' (%s) / RRs: %s" % (
                    self.log_prefix(handler),
                    handler.client_address[0],
                    handler.client_address[1],
                    handler.protocol,
                    reply.q.qname,
                    QTYPE[reply.q.qtype],
                    ",".join([QTYPE[a.rtype] for a in reply.rr])))
        self.log_data(reply)

    def log_truncated(self, handler, reply):
        print("%sTruncated Reply: [%s:%d] (%s) / '%s' (%s) / RRs: %s" % (
                    self.log_prefix(handler),
                    handler.client_address[0],
                    handler.client_address[1],
                    handler.protocol,
                    reply.q.qname,
                    QTYPE[reply.q.qtype],
                    ",".join([QTYPE[a.rtype] for a in reply.rr])))
        self.log_data(reply)

    def log_error(self, handler, e):
        print("%sInvalid Request: [%s:%d] (%s) :: %s" % (
                    self.log_prefix(handler),
                    handler.client_address[0],
                    handler.client_address[1],
                    handler.protocol,
                    e))

    def log_data(self, dnsobj):
        print("\n", dnsobj.toZone("    "), "\n", sep="")


class UDPServer(socketserver.UDPServer):
    allow_reuse_address = True

class TCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class DNSServer(SCIONElement):

    """
        Convenience wrapper for socketserver instance allowing
        either UDP/TCP server to be started in blocking more
        or as a background thread.

        Processing is delegated to custom resolver (instance) and
        optionally custom logger (instance), handler (class), and 
        server (class)

        In most cases only a custom resolver instance is required
        (and possibly logger)
    """
    def __init__(self,
                    sion_topo, 
                    scion_conf,
                    resolver,
                    address="",
                    port=53,
                    tcp=False,
                    logger=None,
                    server=None,
                    sd=None):
        """
            resolver:   resolver instance
            address:    listen address (default: "")
            port:       listen port (default: 53)
            tcp:        UDP (false) / TCP (true) (default: False)
            logger:     logger instance (default: DNSLogger)
            handler:    handler class (default: DNSHandler)
            server:     socketserver class (default: UDPServer/TCPServer)
        """
        self.scion_topo = sion_topo
        self.scion_conf = scion_conf
        self.server_address = IPv4HostAddr(address)
        self.client_address = None
        SCIONElement.__init__(self, self.server_address, self.scion_topo, self.scion_conf)
        self.resolver = resolver
        #Logging mecanism we want to use.
        self.logger = logger or DNSLogger()
        self.scion_daemon  = sd
    def run(self):
        SCIONElement.run(self)

    def clean(self):
        SCIONElement.clean(self)

    def handle_request(self, packet, sender, from_local_socket=True):  
        """
            Handler for the DNSServer. Transparently handles requests
            and hands off lookup to the specified resolver instance.
        """
        self.protocol = 'udp'
        self.client_address = sender
        spkt = SCIONPacket(packet)
        ptype = spkt.hdr.common_hdr.type
        if not( ptype == PT.DNS_REQ or ptype == PT.DNS_REP):
            raise ValueError("We do expect here a DNS packet.")
        packet = spkt.payload
        is_curve = False
        if packet[:8] == b'Q6fnvWj8':
            is_curve = True
            dnscurve_second_pk, dnscurve_nonce, \
                dnscurve_box = dnscurve_decode_streamlined(packet)
            dnscurve_nonce = dnscurve_nonce + ('\0' * 12).encode('utf-8')
            # TODO: fixed values now.
            dnscurve_sk = b'&\\_\xa6\x88DR\xf01\x08v\x1d\x89\xc20\x94i\xb5\xd3\xd0_>\xdf7/]\xe2FZE\x97\xff'
            packet = nacl.crypto_box_curve25519xsalsa20poly1305_open(dnscurve_box, dnscurve_nonce,
                                                        dnscurve_second_pk,
                                                        dnscurve_sk)
        self.logger.log_recv(self, packet)
 
        try:
            rdata = self.get_reply(packet)
            self.logger.log_send(self, rdata)
            rdata = bytes(rdata)
            if is_curve:
                dnscurve_nonce = dnscurve_nonce[:12] + nacl.randombytes(12)
                cyphertext_box = nacl.crypto_box_curve25519xsalsa20poly1305(rdata, dnscurve_nonce, dnscurve_second_pk, dnscurve_sk)
                packet = 'R6fnvWj8'.encode('utf-8') + dnscurve_nonce + cyphertext_box
                rdata = packet
            client_address_ipv4 = IPv4HostAddr(self.client_address[0])
            scion_reply_packet = SCIONPacket.from_values(src=self.server_address, dst=client_address_ipv4, payload=rdata, pkt_type=PacketType.DNS_REP)
            
            #If the communication is intra AD
            if isinstance(spkt.hdr.path, EmptyPath):
                self.send(packet=scion_reply_packet, dst=client_address_ipv4, dst_port=self.client_address[1])
            #if the communication is extra AD
            else:
                spkt.hdr.reverse()
                spkt.payload = rdata
                (next_hop, port) = self.scion_daemon.get_first_hop(spkt)
                self.scion_daemon.send(spkt, next_hop, port)

        except DNSError as err:
            self.logger.log_error(self, err)
        self.client_address = None

    def get_reply(self, data):
        request = DNSRecord.parse(data)
        self.logger.log_request(self, request)

        resolver = self.resolver
        reply = resolver.resolve(request, self)
        self.logger.log_reply(self, reply)
        print("Here is the reply : " + str(reply))
        udplen = 0                  # Max udp packet length (0 = ignore)
        rdata = reply.pack()
        if udplen and len(rdata) > udplen:
            truncated_reply = reply.truncate()
            rdata = truncated_reply.pack()
            self.logger.log_truncated(self, truncated_reply)
        else:
            rdata = reply.pack()

        return rdata


if __name__ == "__main__":
    import doctest
    doctest.testmod(optionflags=doctest.ELLIPSIS)
