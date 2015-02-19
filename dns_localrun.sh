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
#*****************************
#echo "compile crypto library"
#./scion.sh init
#echo "--compiled--"

#Uncomment if necessary.
#*****************************
#echo "Executable"
#chmod +x dns/recursive_resolver.py
#chmod +x dns/authoritative_resolver.py
#chmod +x dns/dnscurve_operations.py
#chmod +x dns/dummy_client.py
#chmod +x dns/top_level_server.py
#echo "Done."

cd dns

#If you want to have it in files, use:
# > allout.txt 2>&1
run_recursive_resolver() {
PYTHONPATH=../ python3.4 ./recursive_resolver.py -z"zone.conf" -p8888 -a"192.33.93.140"
}

run_authoritative_resolver() {
PYTHONPATH=../ python3.4 ./authoritative_resolver.py -z"auth.conf" -p11111 -a"192.33.93.140"
}

run_top_level_server(){
PYTHONPATH=../ python3.4 ./top_level_server.py -z"CHtld.conf" -p9999 -a"192.33.93.140"
}


run_authoritative_resolver&
run_top_level_server&
run_recursive_resolver &


echo "----------------------------------------------------------"
echo " Servers have been initialized, now perform your queries. "
echo "----------------------------------------------------------"

