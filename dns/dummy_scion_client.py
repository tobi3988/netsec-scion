"""
dummy_scion_client.py

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
import argparse
import time
from dnslib.dns import DNSRecord

def main():
    """
    Main function.

    Runs some SCION queries to test the behavior of the DNS application.
    """

    argument_parser = argparse.ArgumentParser(description="Dummy Clients " + \
                                            "  for DNS application testing")

    argument_parser.add_argument("--port", "-p", type=int,                 \
                                default = 30040, metavar = "<port>",         \
                                help = "Resolver's port (default is 30400)")

    argument_parser.add_argument("--address","-a",default="127.1.19.95",
                                metavar="<address>",
                                help="Resolver's address (default is " +
                                 "127.1.19.95)")
    #End user is in ISD 1, AD 19.
    source_address = "127.0.0.11"
    arguments = argument_parser.parse_args()
    #Note that the last "." (root) is automatically added here.
    request_packet = DNSRecord.question("domain1.ch", "SCIONA", "IN")
    a = time.time()
    reply_packet = request_packet.send(src=source_address, dst=arguments.address, port=arguments.port)
    b = time.time()
    print("Temps total : " + str((b-a)))
    reply = DNSRecord.parse(reply_packet)
    print("Reply: " + str(reply))

if __name__ == "__main__":
    main()
    