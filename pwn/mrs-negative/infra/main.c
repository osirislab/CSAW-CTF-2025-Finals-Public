#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *chunks[0x10];
int32_t chunk_sizes[0x10];

void create(){
    printf("(*^▽^*)  ");
    char index_buffer[0x8];
    fgets(index_buffer, 0x8, stdin);
    int index = strtol(index_buffer, NULL, 10);
    if (index < 0 || index >= 0x10 || chunks[index] || chunk_sizes[index] != 0) {
        puts("⚠️  ⛔️⛔️⛔️");
        return;
    }

    printf("(o^∀^o)  ");
    char size_buffer[0x8];
    fgets(size_buffer, 0x8, stdin);
    int size = strtol(size_buffer, NULL, 10);
    if (size <= 0 || size > 0x100) {
        puts("⚠️  ⛔️⛔️⛔️");
        return;
    }

    void *chunk = malloc(size);
    if (chunk < sbrk(0) - 0x20d60 || chunk >= sbrk(0)) {
        puts("⚠️  ⛔️⛔️⛔️");
        return;
    }
    chunks[index] = chunk;
    chunk_sizes[index] = size;

    printf("(｡･ω･｡)ﾉ♡  ");
    fgets(chunks[index], chunk_sizes[index] + 1, stdin);
    chunk_sizes[index] = strlen(chunks[index]);
    puts("⚠️  ✅✅✅");

    return;
}

void copy(){
    printf("(→_→)  ");
    char dst_index_buffer[0x8];
    fgets(dst_index_buffer, 0x8, stdin);
    int dst_index = strtol(dst_index_buffer, NULL, 10);
    if (dst_index < 0 || dst_index >= 0x10 || !chunks[dst_index] || chunk_sizes[dst_index] == 0) {
        puts("⚠️  ⛔️⛔️⛔️");
        return;
    }

    printf("(←_←)  ");
    char src_index_buffer[0x8];
    fgets(src_index_buffer, 0x8, stdin);
    int src_index = strtol(src_index_buffer, NULL, 10);
    if (src_index < 0 || src_index >= 0x10 || !chunks[src_index] || chunk_sizes[src_index] == 0) {
        puts("⚠️  ⛔️⛔️⛔️");
        return;
    }

    printf("(ー_ー)  ");
    char cpy_size_buffer[0x8];
    fgets(cpy_size_buffer, 0x8, stdin);
    int cpy_size = strtol(cpy_size_buffer, NULL, 10);
    if (cpy_size > chunk_sizes[dst_index] || cpy_size > chunk_sizes[src_index]) {
        puts("⚠️  ⛔️⛔️⛔️");
        return;
    }

    memcpy(chunks[dst_index], chunks[src_index], cpy_size);
    puts("⚠️  ✅✅✅");

    return;
}

void delete(){
    printf("( ´_ゝ´)  ");
    char index_buffer[0x8];
    fgets(index_buffer, 0x8, stdin);
    int index = strtol(index_buffer, NULL, 10);
    if (index < 0 || index >= 0x10 || !chunks[index] || chunk_sizes[index] == 0) {
        puts("⚠️  ⛔️⛔️⛔️");
        return;
    }

    size_t mchunk_size = *((size_t *)chunks[index] - 1);
    size_t mchunk_prev_inuse = mchunk_size & 0x1;
    mchunk_size = mchunk_size & ~0x7;
    size_t mchunk_prev_size = *((size_t *)chunks[index] - 2);

    free(chunks[index]);

    if (mchunk_prev_inuse == 0 && mchunk_prev_size >= 0x10 && mchunk_prev_size < 0x1000) {
        size_t consolidate_size = mchunk_prev_size + mchunk_size;
        if (consolidate_size >= 0x11 && consolidate_size < 0x1100) {
            chunks[index] = malloc(consolidate_size - 0x18);
        }
    }

    chunks[index] = NULL;
    chunk_sizes[index] = 0;
    puts("⚠️  ✅✅✅");

    return;
}

void view(){
    printf("(⌐■_■)  ");
    write(1, sbrk(0) - 0x20d60, 0x100);
    puts("⚠️  ✅✅✅");

    return;
}

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    free(malloc(0x1000));

    char choice_buffer[0x8];
    int choice;

    while (1) {
        printf("\n");
        puts("1️⃣  👽👽👽");
        puts("2️⃣  👾👾👾");
        puts("3️⃣  🛸🛸🛸");
        puts("4️⃣  🔮🔮🔮");
        printf("(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧  ");

        fgets(choice_buffer, 0x8, stdin);
        choice = strtol(choice_buffer, NULL, 10);
        if (choice < 1 || choice > 4) {
            puts("❗️  ❓❓❓");
            exit(1);
        }

        switch (choice) {
            case 1:
                create();
                break;
            case 2:
                copy();
                break;
            case 3:
                delete();
                break;
            case 4:
                view();
                break;
        }
    }
}