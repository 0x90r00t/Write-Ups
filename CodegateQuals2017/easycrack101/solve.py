#!/usr/bin/env python2

import subprocess
import requests
import angr
import sys

cookie = {'PHPSESSID':'srsly mate ?'}

def crack(name, addr):
    print 'Cracking %s and find %s' % (name, addr)
    project = angr.Project(name)

    argv1 = angr.claripy.BVS("argv1", 100*8) #since we do not the length now, we just put 100 bytes
    initial_state = project.factory.path(args=[name, argv1])

    #create a path group using the created initial state
    pg = project.factory.path_group(initial_state)

    #symbolically execute the program until we reach the wanted value of the instruction pointer
    pg.explore(find=int(addr, 16))

    found = pg.found[0]
    #ask to the symbolic solver to get the value of argv1 in the reached state
    solution = found.state.se.any_str(argv1)

    solution = solution[:solution.find("\x00")]
    flag = ''
    for x in solution:
        if ord(x) != 0:
            flag += x
    print flag
    return flag

for x in xrange(15, 102):
    prog = 'prob' + str(x)
    command = './offset.py %s \'Good Job\'' % prog
    out = subprocess.check_output(command,shell=True,stderr=subprocess.PIPE)
    addr = out.split('\n')[1]
    command = 'objdump -M intel -D %s | grep %s' % (prog, addr)
    out = subprocess.check_output(command,shell=True,stderr=subprocess.PIPE)
    addr = hex(int(out[0:out.find(':')], 16))
    ret = crack(prog, addr)
    r = requests.post('http://110.10.212.131:8777/auth.php', cookies=cookie, data={'prob':str(x), 'key':ret.rstrip()})
    print r.text
