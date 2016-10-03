#!/bin/bash

make
TMP=`for i in $(objdump -d stage1 -M intel |grep "^ " |cut -f2); do echo -n '\x'$i; done;`
echo -n "stage1 shellcode length: "
perl -e "print \"$TMP\"" | wc -c

TEST=$TMP
perl -e "print \"$TEST\"" > data
