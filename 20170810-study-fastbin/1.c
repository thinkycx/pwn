#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int size = 40 | 0x1;
int main(int argc, char *argv[]) {
    void *buf0, *buf1, *buf2;
    buf0 = malloc(32);
    buf1 = malloc(32);


    free(buf1);
    free(buf0);


    buf0 = malloc(32);
    buf1 = malloc(32);

    read(0, buf0, 64);

    buf2 = malloc(32);


    printf("buf2 is at %p\n", buf2);


    return 0;
}
