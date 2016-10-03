#!/bin/bash

./bfc.py > out.asm && nasm -f bin -o out.com out.asm
#ndisasm -b 16 out.com | less
