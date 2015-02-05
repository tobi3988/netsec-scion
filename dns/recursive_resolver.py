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
from dnslib.dns import QTYPE, RCODE, DNSRecord, CLASS
from dnslib.label import DNSLabel

import time


ZONE={
      
      "domain1.ch.":("111.222.123.234","1,7"),
    }
#        swiss_suffix = "ch."
#        swiss_ip = "192.33.93.140"
#        swiss_port = "9876"
        
#        us_suffix = "us."
#        us_ip = "192.33.93.140"
#        us_port = "6789"


class Toolbox():
    """
    The Utilities class
    
    This class provides some tools to help processing the requests. 
    Most of the tools should be then included in the dnslib library.
    """
    def is_root(self, label):
        """
        Is the provided label pointing towards the root?
        """
        return len(label) > 0 and label[-1]=='.'
        
class Resolver(BaseResolver):
    
    def __init__(self,zone):
        self.zone=zone
        
    def resolve(self, request, handler):
        """
        The resolve method
        
        Processes the resolution of the queries by the recursive resolver.
        The recursive resolver gets the request from the stub resolver and
        performs the recursive resolution before to send the reply back.
        """
        #helper to include in dnslib.
        helper = Toolbox()
        
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        qclass = CLASS[request.q.qclass]
        qname_to_resolve = []
        reply = request.reply()
        if helper.is_root(str(qname)):
            qname_to_resolve.append(str(qname))

        recursive_record = DNSRecord.question(qname, qtype, qclass)
        reply_packet = recursive_record.send("192.33.93.140", 9999)
        reply = DNSRecord.parse(reply_packet)
        
        return reply
        #print("This country does not exist")
            #reply.header.rcode = getattr(RCODE, 'NOTZONE')
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
