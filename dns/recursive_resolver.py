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
from dnslib.dns import QTYPE, RCODE, DNSRecord, DNSError, CLASS, RR, TXT
from dnslib.bimap import Bimap

import time
import random
import socket
#import libnacl



ZONE = {
      "domain1.ch.":("111.222.123.234", "1,7"),
    }
# List of TLD nameservers.
TLDSERVER = Bimap('TLD',
                {'.ch':'192.33.93.140', '.us': "192.33.93.140"},
                DNSError)

class Toolbox():
    """
    The Utilities class
    
    This class provides some tools to help processing the requests. 
    Most of the tools should be eventually included in the dnslib library.
    """
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
            raise ValueError('depth must be >= 0 and <= name length')
        # we can delete the old root
        label = label[:-1]
        return (label[:-depth]), (label[-depth :])
 
class Resolver(BaseResolver):
    
    def __init__(self, zone):
        self.zone = zone
        self.eq = '__eq__'
 #       self.pk, self.sk = libnacl.crypto_sign_keypair()
    def resolve(self, request, handler):
        
        """
        The resolve method
        
        Processes the resolution of the queries by the recursive resolver.
        The recursive resolver gets the request from the stub resolver and
        performs the recursive resolution before to send the reply back.
        """
        # TODO: helper to include in dnslib.
        helper = Toolbox()

#      print("The nacl key pair: ")
#     print("Public: " + self.pk)
#    print("Private: " + self.sk)
        
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        qclass = CLASS[request.q.qclass]
        
        _, country_suffix = helper.split(str(qname))
        # Ip addresses of server to query.
        
        try:
            name_server = TLDSERVER[country_suffix]
        except DNSError: 
            reply = request.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            return reply
        
        
        port = 11111
        if helper.is_root(str(qname)):
            
            reply = None
            is_address = False
            is_answered = False

            start = time.time()
            
            while not is_answered:
                timeout = self.request_time_out(start, 2)
                print("timeout: " + str(timeout))              
                # Query to forward
                recursive_query = DNSRecord.question(qname, qtype, qclass)

                try:
                    ns_reply_packet = recursive_query.send(name_server, port, False, timeout)
                except socket.error:
                    ns_reply_packet = None
                    reply = request.reply()
                    timeout_txt = "The request for: "+ name_server + " encountered a timeout."
                    reply.add_ar(RR(qname,QTYPE.TXT,rdata=TXT(timeout_txt)))
                    reply.header.rcode = RCODE.SERVFAIL
                    return reply

                ns_reply = DNSRecord.parse(ns_reply_packet)
               
                # The recursive resolver is not supposed to obtain questions back.
                if (ns_reply.header.get_qr()) :
                    if QTYPE[request.q.qtype] in ['A', 'AAAA']:
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
                                if str(auth_name) == ar.rname and QTYPE[ar.rtype] in ['A', 'AAAA']:
                                    name_server = str(ar.rdata)
                                else:
                                    print("This case is out of scope.")
                            
                            port = 9999
                    else:
                        print("This case is out of scope.")
                        break;
                else:
                    print("Why do we receive a question? Drop it.")
        else :
            print("Wrong domain format.")
        reply = request.reply()
        reply.header.rcode = RCODE.NXDOMAIN

        """
        PSEUDOCODE OF THE RECURSIVE RESOLVER: 
        Remaining:
        - (Special case, @todo -- caching)
        - (@todo -- DNScurve (init- generate Pk, Sk, etc.)
            - New RR-type.
            - Certificate support
            - new step necessary or NS - included certificate? 
        - The recursive server requests the queried domain from a root server.
            - Since the central root does not exist in SCION, the 
                recursive resolver know all the existing tld addresses.
                It sends the query to the corresponding ISD-DNS-ROOT.
        - The recursive server receives the answer from the ISD-DNS-ROOT
            3-answers type: 
                - Final, complete answer
                    - Send answer back to stub'
                - NS referral, glue || glueless
                    -glue => then ask the provided server
                    -glueless => need to re-query.
                    (We should not allow out of bailiwick queries)
                - CNAME referral
                    - need to re-query.
        Comment: 
        - First it looks in cache for the leftmost part, if not, cut and next one,
        until root.
        """
    
        """
        Receiving the answer: 
        - (header) Parse out/discard questions when we want an answer.
        - (optional) reduce insane ttl
        """ 
        return reply
    def request_time_out(self, start_time, limit_time):
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
        udp_server = DNSServer(resolver, port=self.listening_port,
                               address=self.ip_address)

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
    listening_port = 8888
    
    dns_server = RecursiveServer(server_address, listening_port)
    dns_server.startRecursiveServer()

if __name__ == "__main__":
    main()
