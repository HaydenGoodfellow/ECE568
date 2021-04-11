#Hayden Goodfellow, 1004068386, Hayden.Goodfellow@mail.utoronto.ca
#Joseph Sawaya, 1004760537, joseph.sawaya@mail.utoronto.ca

Part 1 Explanation:
For part 1.1 & 1.2 i used the following dig command: dig utoronto.ca, from the answer to that command i got the ipv4 address 
for utoronto.ca and the nameservers and their addresses. For 1.3 i used: dig utoronto.ca mx, the added mx argument makes it so that we are querying the domain name of 
all mail servers associated with that domain name, i then used: dig utoronto-ca.mail.protection.outlook.com, which is the domain name of the mail server and i got its ipv4 
address. For 1.4, we run the same commands but add @127.0.0.1 -p 45543 which are the address and listen-on port for our BIND server. 

Part 2 Explanation:
For this part we had to implement a proxy server. What I did is that I created a UDP socket and bound it to a port so i could run dig specifying that port as the destination
of the dns server, so my proxy would receive the dig queries, then it would forward those queries to the address and port of the BIND server that I passed in when starting
the proxy server, it would also save the port number of the dig query so it could send back the reply from the BIND server.

Part 3 Explanation:
For this part I had to alter the contents of the DNS packet. I would check if the spoof flag was true, and if the proxy server receives a reply for the domain example.com
it would use scapy to alter the contents of the DNS packet, by changing the ip in the answer section of the packet and the nameserver names in the nameserver section of the
DNS packet, then send the reply back to the dig process.  