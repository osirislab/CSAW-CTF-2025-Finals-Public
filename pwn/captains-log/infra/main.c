#include <stdio.h>
#include <unistd.h>

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    write(1, (char *)&stdout + 2, 2);

    read(0, stdout, 0x40);
    read(0, (char *)stdout + 0x88, 0x40);

    return 0;
}