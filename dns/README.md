:feet: :feet: :feet:

DNS
=====

Python DNS implementation of [SCION](http://www.netsec.ethz.ch/research/SCION)

recursive_resolver.py
--------------
The recursive resolver is provided by the ISP (and should therefore be in each AD containing end-users).  
It takes the end-user queries as input, then forwards those queries to different name-servers and eventually provide the answer to the end-users.
The recursive resolver communicates with the name servers in a secure manner using DNSCurve streamlined format. They therefore generate a cryptographic key pair, then encrypt the queries using a nonce, the keys using elliptic curve cryptography as proposed by DNSCurve.  
For some help run: 
	`top_level_server.py -h`

Parameters:
*	zone file
*	port
*	address
*	log (which options we want to log)

top_level_server.py
--------------
Contains the logic of the TLDs.  
Support DNSCurve for encrypted communication.
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
Support DNSCurve for encrypted communication.
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

* zone.conf	:	used by the recursive resolver
* CHtld.conf	:	used as the .ch (swiss) TLD.
* auth.conf	:	used as an authoritative server for *domain1.ch*

../dns_localrun.sh
--------------
This simple little script is created for the local run of the dns infrastructure.  
It is not included in scion and behave like a local Internet resolver. 
(Useful for Debugging, taking DNS in hand.)


dnslib9.0.1
--------------
[DNSlib](https://pypi.python.org/pypi/dnslib) is a simple library allowing to encode/decode DNS wire-format packets.
It supports 3.2+ python.
*Unfortunately, I had to modify it in order to support DNSCURVE.*
*More details will be provided about my changes.*

Usage:
------
Simple local usage:

Launch the servers:  
`./dns_localrun.sh`

Try some *dig* commands:  

`dig @192.33.93.140 -p8888 NS ethz.ch`

Output:  

	; <<>> DiG 9.9.5-3ubuntu0.2-Ubuntu <<>> @192.33.93.140 -p8888 NS ethz.ch
	; (1 server found)
	;; global options: +cmd
	;; Got answer:
	;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 20927
	;; flags: qr aa rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
	;; QUESTION SECTION:
	;ethz.ch.			IN	NS
	;; ANSWER SECTION:
	ethz.ch.		604800	IN	NS	ns1.ethz.ch.

`dig @192.33.93.140 -p8888 domain1.ch.`
  
Output:  

	; <<>> DiG 9.9.5-3ubuntu0.2-Ubuntu <<>> @192.33.93.140 -p8888 domain1.ch.  
	; (1 server found)  
	;; global options: +cmd  
	;; Got answer:
	;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 52252
	;; flags: qr aa rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
	;; QUESTION SECTION:
	;domain1.ch.			IN	A
	;; ANSWER SECTION:
	domain1.ch.		10800	IN	A	111.222.123.123
	;; Query time: 13 msec
	;; SERVER: 192.33.93.140#8888(192.33.93.140)
	;; WHEN: Thu Feb 19 15:07:23 CET 2015
	;; MSG SIZE  rcvd: 44


* [doc](https://github.com/netsec-ethz/scion/tree/master/doc) contains documentation and material to present SCION
* [infrastructure](https://github.com/netsec-ethz/scion/tree/master/infrastructure)
* [lib](https://github.com/netsec-ethz/scion/tree/master/lib) contains the most relevant SCION libraries
* [topology](https://github.com/netsec-ethz/scion/tree/servers/topology) contains the scripts to generate the SCION configuration and topology files, as well as the certificates and ROT files


