from scapy.all import *

import sys

INTERFACE_NAME = 'br-22184f2413c5'

dst_ip = sys.argv[1]

cur_ttl = 1

while True:
    a = IP(dst=dst_ip, ttl=cur_ttl)
    b = ICMP()

    pkt = a / b

    reply = sr1(pkt, verbose=0, iface=INTERFACE_NAME)

    if reply[ICMP].type == 11:
        print('{} => {}'.format(cur_ttl, reply[IP].src))
        ttl += 1
    elif reply[ICMP].type == 0:
        print('{} => {}'.format(cur_ttl, reply[IP].src))
        break
