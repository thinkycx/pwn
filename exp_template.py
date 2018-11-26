#!/usr/bin/env python
# coding=utf-8
# author: thinkycx
# date: 2018-10-31
from pwn import *
context.local(arch='amd64', os='linux')

def pwn(io):
    if local&debug: gdb.attach(io,'break *0x400641')

if __name__ == '__main__':
    global io, elf, libc, debug
    local, debug = 1, 0
    context.log_level = 'debug'
    filename = './scanf'
    elf = ELF(filename)
    if local:
        io = process(filename, env={"LD_PRELOAD":"/tmp/libc.so"})
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        # context.terminal = ['tmux', '-x', 'sh', '-c']
        context.terminal = ['tmux', 'splitw', '-h' ]
    pwn(io)
    io.interactive()
