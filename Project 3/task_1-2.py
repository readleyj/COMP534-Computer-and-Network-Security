from scapy.all import *

a = IP(src='1.2.3.4', dst='10.0.2.5')
b = ICMP()
p = a/b

send(p)
