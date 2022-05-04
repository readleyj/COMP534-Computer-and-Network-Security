#!/usr/bin/python3
import scapy.all as scapy

INTERFACE_NAME = 'br-22184f2413c5'


def spoof_pkt(pkt):
    if scapy.ICMP in pkt and pkt[scapy.ICMP].type == 8:
        print('Original packet')
        print('Source IP', pkt[scapy.IP].src)
        print('Destination IP', pkt[scapy.IP].dst)

        ip = scapy.IP(src=pkt[scapy.IP].dst,
                      dst=pkt[scapy.IP].src, ihl=pkt[scapy.IP].ihl)
        icmp = scapy.ICMP(
            type=0, id=pkt[scapy.ICMP].id, seq=pkt[scapy.ICMP].seq)
        data = pkt[scapy.Raw].load
        new_pkt = ip/icmp/data

        print('Spoofed packet')
        print('Source IP', new_pkt[scapy.IP].src)
        print('Destination IP', new_pkt[scapy.IP].dst)
        scapy.send(new_pkt, verbose=0)


pkt = scapy.sniff(filter='icmp', prn=spoof_pkt, iface=INTERFACE_NAME)
