#!/usr/bin/python3
from scapy.all import *

INTERFACE_NAME = 'br-22184f2413c5'


def spoof_pkt(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        print('Original packet')
        print('Source IP', pkt[IP].src)
        print('Destination IP', pkt[IP].dst)

        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load
        new_pkt = ip/icmp/data

        print('Spoofed packet')
        print('Source IP', new_pkt[IP].src)
        print('Destination IP', new_pkt[IP].dst)
        send(new_pkt, verbose=0)


pkt = sniff(filter='icmp', prn=spoof_pkt, iface=INTERFACE_NAME)
