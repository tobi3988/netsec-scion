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
from dnslib.server import DNSServer, BaseResolver
from dnslib.dns import QTYPE, RCODE
from dnslib.label import DNSLabel
import time


ZONE={
      
      "domain1.ch.":("111.222.123.234","1,7"),
    }
class Resolver(BaseResolver):
    
    def __init__(self,zone):
        self.zone=zone
    def resolve(self, request, handler):
        swiss_suffix = "ch."
        us_suffix = "us."
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        label = DNSLabel(str(qname))
        if label.matchSuffix(swiss_suffix):
            print("Looking for a swiss domain.")
            #todo: implement the logic here.
        elif label.matchSuffix(us_suffix):
            print("Looking for us domain.")
            #todo: implement the logic here.
        else:
            print("This country does not exist")
            reply.header.rcode = getattr(RCODE, 'NOTZONE')
        return reply
    
class RecursiveServer():
    """
    THE SCION Recursive Resolver.

    The recursive resolver performs the requests for the clients and eventually
    returns the final answer to the latter.
    """
    def __init__(self, ip_address, listening_port):
        self.ip_address = ip_address
        self.listening_port = listening_port

    def startRecursiveServer(self):
        resolver = Resolver(ZONE)
        udp_server = DNSServer(resolver,  port= self.listening_port,
                               address= self.ip_address)

        udp_server.start_thread()
        print("UDP Recursive Resolver listening on port: " +
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
            print("The UDP Recursive Resolver was stopped.") 
                
                
def main():
    """
    Main function.
    """
    server_address = "192.33.93.140"
    listening_port= 8888
    
    dns_server = RecursiveServer(server_address, listening_port)
    dns_server.startRecursiveServer()

if __name__ == "__main__":
    main()
