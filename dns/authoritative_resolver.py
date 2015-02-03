"""
recursive_resolver.py

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

from dnslib.server import BaseResolver, DNSServer
from dnslib.dns import QTYPE, A, RR, TXT, RCODE


ZONE={
      "domain1.ch.":("111.222.123.234","1,7"),
    }

class Resolver(BaseResolver):
    """
    Packet handler.

    Resolves the incoming packet and gives the appropriate answer.
    """
    def __init__(self,zone):
        self.zone=zone

    def resolve(self, request, handler):
        """
        Resolves the incoming queries.
        """
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        label = str(qname)
        if label in self.zone:
            if  qtype == 'A':
                ip_address, isd_ad = self.zone[label]
                msg= "%s::%s::%s"%(label, ip_address, isd_ad)
                reply.add_answer(RR(qname, QTYPE.A, rdata= A(ip_address)))
            elif qtype == 'CNAME':
                print(self.zone[label])
        else:
            print("The requested domain is not known. "
                      + " Sending a NXDOMAIN packet as answer.")
            reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
        return reply

class AuthoritativeServer():
    """
    THE SCION Recursive Resolver.

    The recursive resolver performs the requests for the clients and eventually
    returns the final answer to the latter.
    """
    def __init__(self, ip_address, listening_port):
        self.ip_address = ip_address
        self.listening_port = listening_port

    def startDNSResolver(self):
        resolver = Resolver(ZONE)

        udp_server = DNSServer(resolver, port= self.listening_port,
                               address= self.ip_address)
        udp_server.start_thread()
        print("UDP server listening on port: " +
            str(self.listening_port) +
                " and address: " + str(self.ip_address))
        
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

    ip_address = "192.33.93.140"
    listening_port = 9999
    dns_server = AuthoritativeServer(ip_address, listening_port)
    dns_server.startDNSResolver()

if __name__ == "__main__":
    main()
    