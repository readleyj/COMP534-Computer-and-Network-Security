#!/usr/bin/env python3
import sys

from scapy.all import *

INTERFACE_NAME = 'br-22184f2413c5'

icmp_filter = 'icmp'
tcp_filter = 'tcp and src host 10.9.0.5 and dst port 23'
subnet_filter = 'net 128.230.0.0/16'

filter_map = {
    'icmp': icmp_filter,
    'tcp': tcp_filter,
    'subnet': subnet_filter
}

filter_name_arg = sys.argv[1] if (len(sys.argv) > 1) else None

filter_option = dict.get(filter_map, filter_name_arg, icmp_filter)


def print_pkt(pkt):
    pkt.show()


pkt = sniff(iface=INTERFACE_NAME, filter=filter_option, prn=print_pkt)
