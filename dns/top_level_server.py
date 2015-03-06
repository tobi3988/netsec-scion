"""
top_level_server.py

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
    As a TLD, most of the answers should be referrals and additional answers.
    """
    def __init__(self, zone):
        # We separate the config file info in [RR name| RR type | RR]
        self.zone = [(rr.rname, QTYPE[rr.rtype], rr) for rr in RR.fromZone(zone)]
        self.eq = '__eq__'

    def resolve(self, request, handler):

        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        is_nxdomain = True
        for name, rtype, rr in self.zone:
            # Is the answer of the question in the configuration file?
            if getattr(qname, self.eq)(name):
                if (qtype == rtype or qtype == 'ANY' or rtype == 'CNAME'):
                    is_nxdomain = False
                    reply.add_answer(rr)
                elif(rtype == 'NS'):
                    reply.add_auth(rr)
                    is_nxdomain = False
                # ADD address as additional record
                if rtype in ['CNAME', 'NS', 'MX', 'PTR']:
                    for a_name, a_rtype, a_rr in self.zone:
                        if a_name == rr.rdata.label and (a_rtype in ['A', 'AAAA']):
                            reply.add_ar(a_rr)

        if is_nxdomain:
            print("The requested domain" + str(qname)
                    + " is not known. " + " Sending a NXDOMAIN"
                    + " packet as answer.")
            reply.header.rcode = RCODE.NXDOMAIN
        
        return reply

class TopLevelServer():
    """
    THE SCION Authoritative Server.

    The authoritative server receives the client query and
    answers with the matching response.
    """
    def __init__(self, zone, scion_topo, scion_conf, ip_address, listening_port, logger):
        self.zone = zone
        self.scion_topo = scion_topo
        self.scion_conf = scion_conf
        self.ip_address = ip_address
        self.listening_port = listening_port
        self.logger = logger

    def startDNSResolver(self):
        resolver = Resolver(self.zone)
        print("Content of the Zone File for .ch TLD:")
        print("---------------------------------------\n\n")
        print("Entries: ")
        for rr in resolver.zone:
            print("    -> ", rr[2].toZone(), sep="")
            print("")
        print("---------------------------------------\n\n")
        print("UDP server listening on port: " + 
              str(self.listening_port) + 
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
        print("The UDP server was stopped.")
            

def main():
    """
    Main function.
    """
    argument_parser = argparse.ArgumentParser(description="Top-Level-server " + \
                                            " responsible for many subdomains" + \
                                            " and answering to them by providing referrals of" + \
                                            " authoritative servers.")

    argument_parser.add_argument("--zone", "-z", default="CHtld.conf",
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
                                 help="Log hooks to enable (default:+request," + \
                                 "+reply,+truncated,+error,-recv,-send,-data)")
    arguments = argument_parser.parse_args()
    zone = open(arguments.zone)

    log_prefix = False
    logger = DNSLogger(arguments.log, log_prefix)
    
    dns_server = TopLevelServer(zone, arguments.topo, arguments.conf, arguments.address, arguments.port, logger)
    dns_server.startDNSResolver()
    
if __name__ == "__main__":
    main()
    
