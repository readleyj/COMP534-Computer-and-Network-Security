import scapy.all as scapy

import sys

MAX_TTL = 255

dst = sys.argv[1]

cur_ttl = 1

while cur_ttl < MAX_TTL:
    a = scapy.IP(dst=dst, ttl=cur_ttl)
    b = scapy.ICMP()

    pkt = a / b

    reply = scapy.sr1(pkt, verbose=0, timeout=2)

    if not reply:
        print('{} => * * * *'.format(cur_ttl))
        cur_ttl += 1
        continue

    if reply[scapy.ICMP].type == 11:
        print('{} => {}'.format(cur_ttl, reply[scapy.IP].src))
        cur_ttl += 1
    elif reply[scapy.ICMP].type == 0:
        print('{} => {}'.format(cur_ttl, reply[scapy.IP].src))
        break
