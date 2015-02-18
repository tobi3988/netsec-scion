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

import time

from dnslib.server import BaseResolver
from dnslib.server import DNSServer
from dnslib.server import DNSLogger
from dnslib.dns import QTYPE
from dnslib.dns import RR
from dnslib.dns import RCODE
import argparse

class Resolver(BaseResolver):
    """
    Packet handler.

    Resolves the incoming packet and gives the appropriate answer.
    """
    def __init__(self,zone):
        self.zone = [(rr.rname, QTYPE[rr.rtype], rr) for rr in RR.fromZone(zone)]
        self.eq = '__eq__'

    def resolve(self, request, handler):
        """
        Resolves the incoming queries.
        """
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        is_nxdomain = True
        for name, rtype, rr in self.zone:
            if getattr(qname, self.eq)(name) and (qtype == rtype or 
                                                 qtype == 'ANY' or 
                                                 rtype == 'CNAME'):
                is_nxdomain = False
                reply.add_answer(rr)
                if rtype in ['CNAME', 'NS', 'MX', 'PTR']:
                    for a_name, a_rtype, a_rr in self.zone:
                        if a_name == rr.rdata.label and (a_rtype in ['A', 'AAAA']):
                            reply.add_ar(a_rr)
        if is_nxdomain:
            print("The requested domain: \"" + str(qname)
                    + "\" is not known. " + " Sending a NXDOMAIN"
                    + " packet as answer.")
            reply.header.rcode = RCODE.NXDOMAIN
        return reply

class AuthoritativeServer():
    """
    THE SCION Authoritative Server.

    The authoritative server receives the client query and
    answers with the matching response.
    """
    def __init__(self,zone, ip_address, listening_port, logger):
        self.zone = zone
        self.ip_address = ip_address
        self.listening_port = listening_port
        self.logger = logger

    def startDNSResolver(self):
        resolver = Resolver(self.zone)
        udp_server = DNSServer(resolver, port= self.listening_port,
                               address= self.ip_address, logger= self.logger)
        udp_server.start_thread()

        print("Content of the Zone File for domain1's authoritative server:")
        print("---------------------------------------\n\n")
        print("Entries: ")
        for rr in resolver.zone:
            print("    -> ", rr[2].toZone(), sep="")
            print("")
        print("\n\n---------------------------------------\n\n")
        
        print("UDP server listening on port: " +
            str(self.listening_port) +
                " and address: " + str(self.ip_address))
        print("\n\n---------------------------------------\n\n")
        try:
            while udp_server.isAlive():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            udp_server.stop()
            print("\n")
            print("The UDP server was stopped.")


def main():
    """
    Main function.
    """
    argument_parser = argparse.ArgumentParser(description="Authoritative Resolver "  + \
                                            " responsible for a Zone domain" + \
                                            " and answering to clients" + \
                                            " with respect to their queries.")
    argument_parser.add_argument("--zone", "-z", default="auth.conf",
                                                 metavar="<zone-file>",
                                                      help="Zone file")
    argument_parser.add_argument("--port", "-p", type=int, \
                                default=53, metavar="<port>", \
                                help="Rec. Resolver's port (default is 53)")

    argument_parser.add_argument("--address", "-a", default="192.33.93.140", \
                                metavar="<address>", \
                                help="Rec. Resolver's address (default is  192.33.93.140)")

    argument_parser.add_argument("--log", default="+request,+reply," + \
                                 "+truncated,+error", \
                                 help="Log hooks to enable (default:+request," + \
                                 "+reply,+truncated,+error,-recv,-send,-data)")
    arguments = argument_parser.parse_args()

    zone = open(arguments.zone)
    log_prefix = False
    logger = DNSLogger(arguments.log, log_prefix)
    
    dns_server = AuthoritativeServer(zone, arguments.address, arguments.port, logger)
    dns_server.startDNSResolver()

if __name__ == "__main__":
    main()
    