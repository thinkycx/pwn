from pwn import *
import sys,getopt
import time


args = sys.argv[1:]
context(os='linux', arch='i386')
debug = 1 if '-nd' not in args else 0

proc_name = './test'
local = 1 if '-r' not in args else 0
attach = local & 1
bps = attach & 1
#socat TCP4-LISTEN:10001,fork EXEC:./pwn1
ip = 'chall.pwnable.tw'
port = 10000
io = None

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
   attach()
 
   io.interactive()


if __name__ == '__main__':
	pwn()

