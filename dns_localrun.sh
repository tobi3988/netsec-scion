#!/bin/bash

echo "----------------------------"
echo " DNS Servers Initialisation "
echo "----------------------------"


# The IP address of the DNS Server.
# Since localrun, all servers have the same address.
IPAddress="192.33.93.140";

# The port number of the DNS Server.
# Since localrun, cannot assign same port to several processes,
# For simplicity we allocate random unreserved port #
portNumber_recursiveResolver=8888
portNumber_TLDServer=9999
portNumber_AuthoritativeServer=11111

#Add dnslib/ use python 3.4, args: ip address / port number
#-----------------------------------------------------------

#Uncomment below if necessary.
#echo "compile crypto library"
#./scion.sh init
#echo "--compiled--"


echo "Executable"
chmod +x dns/recursive_resolver.py
echo "Done."

cd dns

PYTHONPATH=../ python3.4 ./recursive_resolver.py -z"zone.conf" -p8888 -a"192.33.93.140"

echo "------------------------------"
echo " The DNS servers were stopped "
echo "------------------------------"
