from scapy.all import *

a = IP(src='1.2.3.4', dst='10.9.0.5')
b = ICMP()
p = a/b

send(p)
