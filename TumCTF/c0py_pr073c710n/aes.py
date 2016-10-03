#!/usr/bin/env python2

from Crypto.Cipher import AES
import binascii
import sys

# this is the sequence of byte we want to have as plaintext
seq = "\xbe\x50\x15\x60\x00\x6a\x7f\x5a\x0f\x05\x48\x89\xf4\xc3\x90\x90"

key = "laxa" * 4
IV = "ABCDEFGHIJKLMNOP"
obj = AES.new(key, AES.MODE_CBC, IV)
# this is the sequence of byte in the binary
ciphertext = "\xC8\x56\xF9\x5D\x1F\x6B\xCD\x27\x5C\xD8\x7E\x91\xA8\x90\xA3\x1d"
plaintext = obj.decrypt(ciphertext)

tmp = plaintext
newIV = ""
for i in range(0, len(IV)):
    newIV += chr(ord(tmp[i]) ^ ord(seq[i]) ^ ord(IV[i]))
sys.stdout.write("IV to use: ")
for x in newIV:
    sys.stdout.write("\\x" + hex(ord(x))[2:])
print ""

keykey = "laxa" * 4
obj2 = AES.new(keykey, AES.MODE_CBC, newIV)
plaintext = ""
ciphertexta = "\xC8\x56\xF9\x5D\x1F\x6B\xCD\x27\x5C\xD8\x7E\x91\xA8\x90\xA3\x1d"
plaintexta = obj2.decrypt(ciphertexta)
assert(plaintexta == seq)
