"""
recursive_resolver.py

Copyright 2015 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from lib.crypto import nacl
from dnslib.server import DNSServer
from dnslib.server import DNSLogger
from dnslib.server import BaseResolver
from dnslib.dns import QTYPE
from dnslib.dns import RCODE
from dnslib.dns import DNSRecord
from dnslib.dns import DNSError
from dnslib.dns import CLASS
from dnslib.dns import RR
from dnslib.dns import TXT
from dnslib.bimap import Bimap

import time
import random
import socket
import argparse
from dns.dnscurve_operations import dnscurve_generate_nonce
from endhost.sciond import SCIONDaemon
from lib.packet.host_addr import IPv4HostAddr
import logging
from lib.packet.scion import SCIONPacket

# List of TLD nameservers.
# Many alternatives to create this.
TLDSERVER = Bimap('TLD',
                {'.ch':'127.1.17.81', '.us': "127.2.25.81"},
                DNSError)


class Resolver(BaseResolver):

    """
    The Resolver of the recursive server.

    Implements the logic of the recursive resolver, standing
    between the stub resolver and the name servers. It forwards
    the request of the client and eventually replies back.
    """
    def __init__(self, zone, address="", handler= None, scion_daemon = None):
        self.eq = '__eq__'
        # We separate the config file info in [RR name| RR type | RR]
        self.zone = [(rr.rname, QTYPE[rr.rtype], rr) for rr in RR.fromZone(zone)]
        self.pk, self.sk = nacl.crypto_box_curve25519xsalsa20poly1305_keypair()
        self.address = address
        self.scion_daemon = scion_daemon

    def resolve(self, request, handler):

        """
        The resolve method.

        Processes the resolution of the queries by the recursive resolver.
        The recursive resolver gets the request from the stub resolver and
        performs the recursive resolution before sending back the reply.
        """

        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        qclass = CLASS[request.q.qclass]

        #TODO: Read and implement this.
        """
        PSEUDOCODE OF THE RECURSIVE RESOLVER: 
        Remaining:
        - (Special case, @todo -- caching)
        - (@todo -- DNScurve (init- generate Pk, Sk, etc.)
            - New RR-type.
            - Certificate support
            - new step necessary or NS - included certificate? 
        Comment: 
        - First it looks in cache for the leftmost part, if not, cut and next one,
        until root.
        
        Receiving the answer: 
        - (optional) reduce insane ttl
        """

        try:
            _, country_suffix = self.split(str(qname))
            name_server = TLDSERVER[country_suffix]
        except ValueError:
            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            error_msg = "Invalid domain name."
            reply.add_answer(RR(qname,QTYPE.TXT,rdata=TXT(error_msg)))
            return reply
        except DNSError:
            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        if self.is_root(str(qname)):
            reply = None
            is_address = False
            is_answered = False
            start = time.time()

            while not is_answered:
                timeout = self.request_time_out(start, 20000)

                # Query to forward
                recursive_query = DNSRecord.question(qname, qtype, qclass)
                recursive_query.is_curve = True

                # The nonce is extended using 12 null bytes.
                recursive_query.dnscurve_nonce = dnscurve_generate_nonce()\
                                                + bytes('\0' * 12, 'utf-8')
                recursive_query.dnscurve_pk = self.pk
                recursive_query.dnscurve_sk = self.sk
                
                #FIXME: The pk of the Name server should obviously be retrieved.
                recursive_query.dnscurve_second_pk = b'#!u\x14w\xc8\x99\x98,\xba`0\xc2\xb86\xe3\xc7\x7f\x05\x1f\xd1c\x81\x9d\x0c\x8d\x91\xbc\xa0L^b'
                # This is the corresponding secret key.
                # fixed_obtained_sk = b'&\\_\xa6\x88DR\xf01\x08v\x1d\x89\xc20\x94i\xb5\xd3\xd0_>\xdf7/]\xe2FZE\x97\xff'

                try:
                    #FIXME: currently we only take the first path that is received.
                    #I think we could provide a round robin or other ways to select paths. 
                    #FIXME: Temporary hack to make it work. provide a better design.
                    ns_reply_packet = recursive_query.send(src=self.address, dst=name_server, timeout=timeout, sd= self.scion_daemon)
                except socket.error:
                    ns_reply_packet = None
                    reply = request.reply()
                    timeout_txt = "The request for: " + name_server + " timed out."
                    reply.add_ar(RR(qname, QTYPE.TXT, rdata=TXT(timeout_txt)))
                    reply.header.rcode = RCODE.SERVFAIL
                    return reply
                
                ns_reply = DNSRecord.parse(ns_reply_packet)
                # Drop questions when reply is expected.
                if ns_reply.header.get_qr():
                    if QTYPE[request.q.qtype] in ['A', 'AAAA', 'SCIONA']:
                        is_address = True
                        if ns_reply.rr:
                            reply = request.reply()
                            for rr in ns_reply.rr:
                                reply.add_answer(rr)
                            is_answered = True
                            return reply
                    if QTYPE[request.q.qtype] in ['CNAME', 'NS', 'MX', 'PTR']:
                        if ns_reply.rr:
                            reply = request.reply()
                            for rr in ns_reply.rr:
                                reply.add_answer(rr)
                            is_answered = True
                            return reply
                    if ns_reply.auth:
                        reply = request.reply()
                        for rauth in ns_reply.auth:
                            reply.add_auth(rauth)
                        if ns_reply.ar:
                            for ar in ns_reply.ar:
                                reply.add_ar(ar)
                        if not is_address:
                            is_answered = True
                            return reply
                        else:
                            random_auth_record = random.choice(reply.auth)
                            auth_name = random_auth_record.rdata
                            for ar in reply.ar:
                                if str(auth_name) == ar.rname and QTYPE[ar.rtype] in ['A', 'AAAA', 'SCIONA']:
                                    name_server = str(ar.rdata)
                                else:
                                    print("This case is out of scope.")
                    else:
                        print("This case is out of scope.")
                        break
                else:
                    print("Why do we receive a question? Drop it.")
        else :
            print("Wrong domain format.")
        reply = request.reply()
        reply.header.rcode = RCODE.NXDOMAIN
        return reply

    def request_time_out(self, start_time, limit_time):
        """
        Computes the remaining time before timeout.
        
        This function is used to compute the timeout
        and return an error to the client.
        """
        now_time = time.time()
        # Time can sometimes go a bit backward
        # We handle it.
        if (now_time < start_time):
            if start_time - now_time > 1:
                raise TimeoutError("Time going backwards.")
            else:
                now_time = start_time
        expired_time = now_time - start_time
        if expired_time > limit_time:
            raise TimeoutError("Time expired.")
        remaining_time = limit_time - expired_time
        return min(remaining_time, limit_time)

    def is_root(self, label):
        """
        Is the provided label pointing towards the root?
        """
        return len(label) > 0 and label[-1] == '.'

    def split(self, label, depth=3):
        """
        Split the label into prefix and suffix at depth.

        returns tuple (prefix, suffix)
        works because ISO Country names = 2 char.
        """
        length = len(label)
        if depth == 0:
            return (label, None)
        elif depth == length:
            return (None, label)
        elif depth < 0 or depth > length:
            raise ValueError('Wrong label format(depth must be >= 0 and <= name length)')
        # we can delete the old root
        label = label[:-1]

        return (label[:-depth]), (label[-depth :])


class RecursiveServer():
    """
    THE SCION Recursive Resolver.

    The recursive resolver performs the requests for the clients and eventually
    returns the final answer to the latter.
    """
    def __init__(self, zone, scion_topo, scion_conf, ip_address, listening_port, is_core, log):
        self.zone = zone
        self.scion_topo = scion_topo
        self.scion_conf = scion_conf
        self.ip_address = ip_address
        self.listening_port = listening_port
        self.logger = log

    def start_recursive_server(self):
        """
        Initiates the Recursive Resolver's routine.

        Reads the Zone file containing necessary mappings and
        starts the server. The server listens only udp queries.
        """
        sub1, sub2, sub3, _= str(self.ip_address).split(".")
        daemon_address = (sub1 +"." + sub2 +"." + sub3 +"." + "99")
        #DEBUG:
        #self.scion_topo = "../topology/ISD1/topologies/ISD:1-AD:19-V:0.json"
        sd = SCIONDaemon.start(IPv4HostAddr(daemon_address), self.scion_topo, False)
        resolver = Resolver(zone=self.zone,address=self.ip_address, scion_daemon= sd)
        print("Content of the Zone File for Recursive Resolver:")
        print("---------------------------------------\n\n")
        print("Entries: ")
        for rr in resolver.zone:
            print("    -> ", rr[2].toZone(), sep="")
            print("")
        print("UDP Recursive Resolver listening on port: " + 
              str(self.listening_port)                     +
             " and address: " + str(self.ip_address))
        print("\n\n---------------------------------------\n\n")
        udp_server = DNSServer(self.scion_topo, self.scion_conf, resolver, port=self.listening_port,
                               address=self.ip_address, logger=self.logger)
        try:
            udp_server.run()
        except KeyboardInterrupt:
            pass
        finally:
            udp_server.clean()
            print("\n")
            print("The UDP Recursive Resolver was stopped.") 


def main():
    """
    Main function.

    Starts the DNS Recursive Resolver.
    """
    argument_parser = argparse.ArgumentParser(description="Recursive resolver " + \
                                            " inside ISP taking queries from end users" + \
                                            " and answering to them by recursively querying" + \
                                            " authoritative servers.")
    argument_parser.add_argument("--zone", "-z", default="zone.conf",
                                                 metavar="<zone-file>",
                                                      help="Zone file")
    argument_parser.add_argument("--topo", "-t", default="", metavar="<topo-file>", help = "Topo file")
    argument_parser.add_argument("--conf", "-c", default="", metavar="<conf-file>", help = "SCION conf")
    argument_parser.add_argument("--port", "-p", type=int, \
                                default=30040, metavar="<port>", \
                                help="Rec. Resolver's port (default is 30040)")

    argument_parser.add_argument("--address", "-a", default="127.0.0.1", \
                                metavar="<address>", \
                                help="Rec. Resolver's address (default is  127.0.0.1)")

    argument_parser.add_argument("--log", default="+request,+reply," + \
                                 "+truncated,+error", \
                                 help="Log hooks to enable (default: +request," + \
                                 "+reply,+truncated,+error,-recv,-send,-data)")
    arguments = argument_parser.parse_args()
    zone = open(arguments.zone)
    #Recursive resolver located in the ISP (Each AD has a RR).
    is_core = False
    log_prefix = False
    logger = DNSLogger(arguments.log, log_prefix)

    dns_server = RecursiveServer(zone, arguments.topo, arguments.conf, arguments.address, \
                                  arguments.port, is_core, logger)
    dns_server.start_recursive_server()
    logging.basicConfig(level=logging.DEBUG)
if __name__ == "__main__":
    main()
