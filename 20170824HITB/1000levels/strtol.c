#include<stdio.h>
#include<string.h>
void main()
{
    char buf[10]="\x00\x31\x00";
    int a ;
    a = 7;
    a = strtol(buf,0,10);
    printf("%d",a);
}
