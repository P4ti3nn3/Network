#!/usr/bin/python3
from scapy.all import *

def ping_response(packet):
    if (packet[2].type == 8):
        dst = packet[1].dst
        src = packet[1].src
        seq = packet[2].seq
        id = packet[2].id
        if len(packet) >= 4:
            load = packet[3].load
        else:
            load = None
        reply = IP(src=dst, dst=src)/ICMP(type=0, id=id, seq=seq)/load
        send(reply, iface="eth1")

sniff(iface="eth1", prn=ping_response, filter="icmp")
