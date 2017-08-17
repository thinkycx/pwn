#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    void *p = malloc(32);
    char buf[8];
    read(0, buf, 0x80);


    free(p);
    malloc(32);
}
