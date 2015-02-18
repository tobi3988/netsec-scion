DNS
=====

Python DNS implementation of [SCION](http://www.netsec.ethz.ch/research/SCION)

:feet: :feet: :feet:

recursive_resolver.py
--------------
This is provided by the ISP (and should therefore be in each AD containing end-users).
It takes the end-user queries as input, then forwards those queries to different name-servers and eventually provide the answer to the end-users.
The recursive resolver communicate with the name servers in a secure manner using DNSCurve. They therefore generate a cryptographic key pair, then encrypt the queries using a nonce, the keys using elliptic curve cryptography as proposed by DNSCurve.

top_level_server.py
--------------
Contains the logic of the TLDs.
For some help run: 
	`top_level_server.py -h`

The zone file can be specified and contains the zone information.

Parameters:
*	zone file
*	port
*	address
*	log (which options we want to log)

authoritative_resolver.py
--------------

Contains the resolver for the *authoritative server*.
The authoritative resolver is responsible for his zone and answers queries
with the matching data.
For some help run: 
	`authoritative_resolver.py -h`

The zone file can be specified and contains the zone information.

Parameters:
*	zone file
*	port
*	address
*	log (which options we want to log)

dummy_client.py
--------------
A client sending queries to the server and printing the answers.
This class is used for testing purpose.
For some help run: 
	`dummy_client.py -h`

Parameters:
*	port
*	address (the client's ISP's recursive resolver address)

dnscurve_opterations.py
--------------
This file provides some DNSCurve tools that are used for the encryption of the DNS packets.

config-files
--------------
*zone.conf	:	used by the recursive resolver
*CHtld.conf	:	used as the .ch (swiss) TLD.
*auth.con	:	used as an authoritative server for *domain1.ch*

dnslib9.0.1
--------------
[DNSlib](https://pypi.python.org/pypi/dnslib) is a simple library allowing to encode/decode DNS wire-format packets.
It supports 3.2+ python.
*Unfortunately, I had to modify it in order to support DNSCURVE.*
*More details will be provided about my changes.*


* [doc](https://github.com/netsec-ethz/scion/tree/master/doc) contains documentation and material to present SCION
* [infrastructure](https://github.com/netsec-ethz/scion/tree/master/infrastructure)
* [lib](https://github.com/netsec-ethz/scion/tree/master/lib) contains the most relevant SCION libraries
* [topology](https://github.com/netsec-ethz/scion/tree/servers/topology) contains the scripts to generate the SCION configuration and topology files, as well as the certificates and ROT files


