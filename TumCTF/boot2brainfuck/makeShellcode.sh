#!/bin/bash

nasm -f bin -o test.com DOS_file_reader.asm
ndisasm -b 16 test.com > disas
./BFgenerator.py | ./testBF.sh
rm out.asm
#rm disas
