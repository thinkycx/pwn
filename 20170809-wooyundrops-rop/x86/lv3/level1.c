#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
/*
gcc -fno-stack-protector -o level2 level1.c -m32
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
*/

void vulnerable_function() {
    char buf[128];
    read(STDIN_FILENO, buf, 256);
}

int main(int argc, char** argv) {
    vulnerable_function();
    write(STDOUT_FILENO, "Hello, World\n", 13);
}
