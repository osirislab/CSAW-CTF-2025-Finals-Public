#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define MAX_CELL 0x10
#define MAX_CELL_AREA 0x480

#define MAX_BUFFER_SIZE 0x8

void *cells[MAX_CELL];
int16_t cell_areas[MAX_CELL];

void strengthen_security() {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 0, 3),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("prctl(PR_SET_NO_NEW_PRIVS) failed");
        exit(EXIT_FAILURE);
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
        perror("prctl(PR_SET_SECCOMP) failed");
        exit(EXIT_FAILURE);
    }
}

int main() {
    strengthen_security();

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    write(1, "In the cold silence of orbit lies a prison, the most heavily guarded penitentiary in space.\n", 92);
    write(1, "Each cell is sealed within a military-class force field, reserved only for the most dangerous criminals.\n", 105);
    write(1, "Is there a flaw in this impenetrable fortress? Well, that's for you to find out.\n", 81);

    free(malloc(0x1000));

    char choice_buffer[MAX_BUFFER_SIZE];
    int choice;

    void *cell = NULL;
    char number_buffer[MAX_BUFFER_SIZE];
    int number;
    char area_buffer[MAX_BUFFER_SIZE];
    int area;

    while (1) {
        write(1, "\n", 1);
        write(1, "Please make a choice:\n", 22);
        write(1, "[1] Build Cell\n", 15);
        write(1, "[2] Purge Cell\n", 15);
        write(1, "[3] Assign Cell\n", 16);
        write(1, "[4] Inspect Cell\n", 17);
        write(1, ">> ", 3);

        read(0, choice_buffer, MAX_BUFFER_SIZE);
        choice = atoi(choice_buffer);
        memset(choice_buffer, 0, MAX_BUFFER_SIZE);

        switch (choice) {
            case 1:
                write(1, "Number: ", 8);
                read(0, number_buffer, MAX_BUFFER_SIZE);
                number = atoi(number_buffer);
                memset(number_buffer, 0, MAX_BUFFER_SIZE);
                if (number < 0 || number >= MAX_CELL || cells[number] || cell_areas[number]) {
                    write(1, "Invalid number!\n", 16);
                    continue;
                }
            
                write(1, "Area: ", 6);
                read(0, area_buffer, MAX_BUFFER_SIZE);
                area = atoi(area_buffer);
                memset(area_buffer, 0, MAX_BUFFER_SIZE);
                if (area > MAX_CELL_AREA) {
                    write(1, "Invalid area!\n", 14);
                    continue;
                }

                cell = malloc(area);
                if (cell < sbrk(0) - 0x20d60 || cell > sbrk(0)) {
                    write(1, "Invalid cell?\n", 14);
                    exit(1);
                }

                cells[number] = cell;
                cell_areas[number] = area;

                write(1, "Cell built successfully!\n", 25);
                break;
            case 2:
                write(1, "Number: ", 8);
                read(0, number_buffer, MAX_BUFFER_SIZE);
                number = atoi(number_buffer);
                memset(number_buffer, 0, MAX_BUFFER_SIZE);
                if (number < 0 || number >= MAX_CELL || !cells[number] || !cell_areas[number] || cells[number] < sbrk(0) - 0x20d60 || cells[number] > sbrk(0)) {
                    write(1, "Invalid number!\n", 16);
                    continue;
                }

                free(cells[number]);

                write(1, "Cell purged successfully!\n", 25);
                break;
            case 3:
                write(1, "Number: ", 8);
                read(0, number_buffer, MAX_BUFFER_SIZE);
                number = atoi(number_buffer);
                memset(number_buffer, 0, MAX_BUFFER_SIZE);
                if (number < 0 || number >= MAX_CELL || !cells[number] || !cell_areas[number] || cells[number] < sbrk(0) - 0x20d60 || cells[number] > sbrk(0)) {
                    write(1, "Invalid number!\n", 16);
                    continue;
                }

                write(1, "Inmates: ", 9);
                read(0, cells[number], cell_areas[number]);

                write(1, "Cell assigned successfully!\n", 28);
                break;
            case 4:
                write(1, "Number: ", 8);
                read(0, number_buffer, MAX_BUFFER_SIZE);
                number = atoi(number_buffer);
                memset(number_buffer, 0, MAX_BUFFER_SIZE);
                if (number < 0 || number >= MAX_CELL || !cells[number] || !cell_areas[number] || cells[number] < sbrk(0) - 0x20d60 || cells[number] > sbrk(0)) {
                    write(1, "Invalid number!\n", 16);
                    continue;
                }

                write(1, cells[number], cell_areas[number]);

                write(1, "Cell inspected successfully!\n", 29);
                break;
            default:
                write(1, "Invalid choice!\n", 16);
                break;
        }
    }

    return 0;
}