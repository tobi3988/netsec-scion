"""
dummy_client.py

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
from dnslib.dns import DNSRecord


def main():
    """
    Main function.
    """
    port_number= 9999
    address = "192.33.93.140"

    #Note that the last "." (root) is automatically added here.
    request_packet = DNSRecord.question("domain1.ch", "A", "IN")
    reply_packet = request_packet.send("192.33.93.140", port_number)
    reply = DNSRecord.parse(reply_packet)
    print("A record reply for existing domain1.ch.:")
    print(reply)

    nx_request_packet = DNSRecord.question("ethz.ch", "A", "IN")
    nx_reply_packet = nx_request_packet.send("192.33.93.140", port_number)
    nx_reply= DNSRecord.parse(nx_reply_packet)
    print("\n\nReply for non existing domain:")
    print(nx_reply)
    
if __name__ == "__main__":
    main()
    