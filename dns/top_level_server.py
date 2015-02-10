"""
top_level_server.py

Copyright 2014 ETH Zurich

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

from dnslib.server import BaseResolver, DNSServer, DNSLogger
from dnslib.dns import QTYPE, RR, RCODE

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

        for name, rtype, rr in self.zone:
            # Is the answer of the question in the configuration file?
            if getattr(qname, self.eq)(name) and (qtype == rtype or 
                                                 qtype == 'ANY' or 
                                                 rtype == 'CNAME'):
                if (qtype == 'NS'):
                    reply.add_auth(rr)
                else:
                    reply.add_answer(rr)
                # ADD address as additional record
                if rtype in ['CNAME', 'NS', 'MX', 'PTR']:
                    for a_name, a_rtype, a_rr in self.zone:
                        if a_name == rr.rdata.label and (a_rtype in ['A', 'AAAA']):
                            reply.add_ar(a_rr)

        if not reply.auth or not reply.ar:
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
    def __init__(self, zone, ip_address, listening_port, logger):
        self.zone = zone
        self.ip_address = ip_address
        self.listening_port = listening_port
        self.logger = logger

    def startDNSResolver(self):
        resolver = Resolver(self.zone)

        udp_server = DNSServer(resolver, port=self.listening_port,
                               address=self.ip_address, logger=self.logger)
        udp_server.start_thread()
        
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

    server_address = "192.168.0.11"
    listening_port = 11111
    zone_file = "CHtld.conf"
    zone = open(zone_file)


    log_prefix = False
    logger = DNSLogger("+request,+reply,+truncated,+error,-recv,-send,-data", log_prefix)
    
    dns_server = TopLevelServer(zone, server_address, listening_port, logger)
    dns_server.startDNSResolver()
    
if __name__ == "__main__":
    main()
    
