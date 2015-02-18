"""
dummy_client.py

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
from dnslib.dns import DNSRecord
import argparse

def main():
    """
    Main function.

    Runs some queries to test the behavior of the DNS application.
    """
    argument_parser = argparse.ArgumentParser(description="Dummy Clients " + \
											"  for DNS application testing")

    argument_parser.add_argument("--port", "-p", type=int, 				\
								default = 8888, metavar = "<port>", 		\
								help = "Resolver's port (default is 53)")

    argument_parser.add_argument("--address","-a",default="192.33.93.140", 			 \
								metavar="<address>", 								 \
                        		help="Resolver's address (default is  192.33.93.140)")

    arguments = argument_parser.parse_args()


    #Note that the last "." (root) is automatically added here.
    request_packet = DNSRecord.question("domain1.ch", "A", "IN")
    reply_packet = request_packet.send(arguments.address, arguments.port)
    reply = DNSRecord.parse(reply_packet)
    print(request_packet)
    print("----")
    print(reply)
    print("\n\n-----------------------\n\n")
    nx_request_packet = DNSRecord.question("ethz.ch", "NS", "IN")
    nx_reply_packet = nx_request_packet.send(arguments.address, arguments.port)
    nx_reply= DNSRecord.parse(nx_reply_packet)
    print(nx_request_packet)
    print("----")
    print(nx_reply)
    print("\n\n-----------------------\n\n")
    cname_request_packet = DNSRecord.question("domain1.nl", "CNAME", "IN")
    cname_reply_packet = cname_request_packet.send(arguments.address, arguments.port)
    cname_reply = DNSRecord.parse(cname_reply_packet)
    print(cname_request_packet)
    print("----")
    print(cname_reply)

if __name__ == "__main__":
    main()
    