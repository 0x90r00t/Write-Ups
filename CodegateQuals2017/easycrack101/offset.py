#!/usr/bin/env python2

import struct
import sys

if len(sys.argv) != 3:
    print "usage: ./offset.py path string"
    exit()

with open(sys.argv[1], "rb") as f:
    data = f.read()

type = ord(data[0x4])
t = ord(data[0x10])
if type == 1:
    print "Binary is 32 bits"
elif type == 2:
    print "Binary is 64 bits"
else:
    print "Binary is fucked up"
    exit()

if type == 1:
    EOP = struct.unpack("<I", data[0x18:0x18 + 4])[0]
elif type == 2:
    EOP = struct.unpack("<Q", data[0x18:0x18 + 8])[0]

offset = int(hex(EOP)[:-3] + "000", 16)

pos = data.find(sys.argv[2])
if pos == -1:
    print "Couldn't find %s in the binary" % sys.argv[2]
    exit()
if t == 3: # if library
    print hex(pos)
else:
    print hex(pos + offset)
