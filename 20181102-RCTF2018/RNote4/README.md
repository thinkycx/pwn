## RCTF2018 Note4

这题只开了NX和CANARY，提供了三个功能：增加chunk、修改chunk和删除chunk。

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // eax
  char menu_choice; // [rsp+17h] [rbp-9h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  init_sub_400AD2();
  if ( (signed int)a1 > 1 )                     // dynamicly set alarm params
  {
    v3 = atoi(a2[1]);
    alarm(v3);
  }
  menu_choice = 0;
  while ( 1 )
  {
    read_sub_4007C6((__int64)&menu_choice, 1u); // read 1 byte
    switch ( menu_choice )
    {
      case 1:                                   // not '1' ; python input 1
        add_sub_400849();
        break;
      case 2:
        change_sub_400984();
        break;
      case 3:
        delete_sub_400A32();
        break;
      case 4:
        exit(0);
        break;
    }
  }
}
```

增加chunk中首先calloc一个0x10的chunk1，再read size后申请calloc size大小的chunk2，并把&chunk2保存在chunk1[1]中，把size保存在chunk1[0]中。&chunk1保存在bss段一个s数组中。

```c
unsigned __int64 sub_400849()
{
  unsigned __int8 size_v1; // [rsp+Bh] [rbp-15h]
  int i; // [rsp+Ch] [rbp-14h]
  _QWORD *chunk1_v3; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( chunk_number_dword_6020A0 > 32 )
    exit(-1);
  size_v1 = 0;
  chunk1_v3 = calloc(0x10uLL, 1uLL);            // malloc 0x10*1 and memset to 0
  if ( !chunk1_v3 )
    exit(-1);
  read_sub_4007C6((__int64)&size_v1, 1u);
  if ( !size_v1 )
    exit(-1);
  chunk1_v3[1] = calloc(size_v1, 1uLL);
  if ( !chunk1_v3[1] )
    exit(-1);
  read_sub_4007C6(chunk1_v3[1], size_v1);
  *chunk1_v3 = size_v1;
  for ( i = 0; i <= 31 && s[i]; ++i )
    ;
  s[i] = chunk1_v3;
  ++chunk_number_dword_6020A0;
  return __readfsqword(0x28u) ^ v4;
}
```

修改chunk，根据下标从s中取出&chunk1，拿到chunk1中保存的chunk2的地址后，read size，再read size大小的数据到chunk2中。由于size可控，堆溢出。

```c
// modify chunk in s (must have ptr in s)
unsigned __int64 sub_400984()
{
  unsigned __int8 choice_v1; // [rsp+Eh] [rbp-12h]
  unsigned __int8 size_v2; // [rsp+Fh] [rbp-11h]
  _QWORD *chunk_v3; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  choice_v1 = 0;
  read_sub_4007C6((__int64)&choice_v1, 1u);
  if ( !s[choice_v1] )
    exit(-1);
  chunk_v3 = s[choice_v1];
  size_v2 = 0;
  read_sub_4007C6((__int64)&size_v2, 1u);       // heap overflow!
  read_sub_4007C6(chunk_v3[1], size_v2);
  return __readfsqword(0x28u) ^ v4;
}
```



删除chunk，read offset从s中取出&chunk1，先free chunk1[1]，也就是先freechunk2，再free chunk1。如果offset不对，则会SIGSEGV，&chunk1为0，free(0x8)。

```c
unsigned __int64 sub_400A32()
{
  unsigned __int8 choice_v1; // [rsp+7h] [rbp-9h]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  choice_v1 = 0;
  read_sub_4007C6((__int64)&choice_v1, 1u);
  if ( choice_v1 > 0x20u )                      // read choice and free , choice only < 0x20 vuln!!!
    exit(-1);
  free(*((void **)s[choice_v1] + 1));           // free 0x10 chunk
  free(s[choice_v1]);                           // free chunk
  s[choice_v1] = 0LL;
  return __readfsqword(0x28u) ^ v2;
}
```



堆溢出时，size的范围是1byte，0-0xff，可以溢出后一个0x10chunk1的chunk1[1]，可以控制其中的指针，update后一个chunk时，可以实现任意地址写0-0xff。堆溢出转化为任意地址写。

没有开RELRO，gdb中可以看出.dynamic段是可写的，且没有开aslr，利用方式：写free的string table为system，在bss上写/bin/sh后，堆溢出chunk1[1]为/bin/sh的地址，调用free就可以getshell。

## 总结
heap overflow导致可以控制chunk中的指针实现任意地址写，由于dynamic可写，修改.strtab可以劫持还未调用的函数。
