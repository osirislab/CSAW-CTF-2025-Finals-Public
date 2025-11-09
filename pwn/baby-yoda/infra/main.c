#include <stdio.h>
#include <unistd.h>

char food1[0x50];

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("A long time ago in a galaxy far, far away... %p\n", main);

    puts("Baby Yoda is hungry! Give it some food!");
    read(0, food1, sizeof(food1));

    puts("Baby Yoda is still hungry! Give it more food!");
    char food2[0x20];
    gets(food2);

    return 0;
}