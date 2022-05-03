import scapy.all as scapy

a = scapy.IP(src='1.2.3.4', dst='10.9.0.5')
b = scapy.ICMP()
p = a/b

scapy.send(p)
