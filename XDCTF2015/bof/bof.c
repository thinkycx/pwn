/*
 * gcc bof.c -m32 -fno-stack-protector -o bof
 * https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/advanced_rop/
 * ret2dlresolve
 * */
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln()
{
    char buf[100];
    setbuf(stdin, buf);
    read(0, buf, 256);
}
int main()
{
    char buf[100] = "Welcome to XDCTF2015~!\n";

    setbuf(stdout, buf);
    write(1, buf, strlen(buf));
    vuln();
    return 0;
}
