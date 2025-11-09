#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

void initialize_workbench() {
    printf("\n");
    puts("Initializing workbench...");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    alarm(10);

    puts("Workbench initialized!");
    printf("\n");
}

void* build_armor() {
    printf("\n");
    puts("Please provide the core prototype of the armor you want to build! Remember to design each of the 16 pieces as strong as possible!");

    void *armor = mmap((void *)(0xdeadbeef0000), 16 * 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (armor == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < 16; i++) {
        printf("Piece %d: ", i + 1);
        fgets((armor + i * 0x1000), 0x40 + 1, stdin);
    }

    mprotect(armor, 16 * 0x1000, PROT_READ | PROT_EXEC);

    puts("Such regular armor is far from enough! An enhancement has to be made!");
    printf("\n");

    return armor;
}

void choose_addon() {
    printf("\n");
    puts("Choose only one add-on for your armor carefully! It's a one-time operation that decides your destiny!");
    puts("[1] Attack Enhancement -- Plasma Cutter");
    puts("[2] Defense Enhancement -- Stasis Module");
    puts("[3] Stealth Enhancement -- The Cloak");

    int sys_a;
    int sys_b;
    int sys_c;

    while (1) {
        printf(">> ");

        int choice;
        if (scanf("%d", &choice) != 1 || choice < 1 || choice > 3) {
            puts("Invalid choice!");
            int c;
            while ((c = getchar()) != '\n' && c != EOF);
            continue;
        }
        getchar();

        if (choice == 1) {
            sys_a = __NR_close;
            sys_b = __NR_exit;
            sys_c = __NR_exit_group;
            break;
        } else if (choice == 2) {
            sys_a = __NR_clock_gettime;
            sys_b = __NR_clock_getres;
            sys_c = __NR_clock_nanosleep;
            break;
        } else if (choice == 3) {
            sys_a = __NR_ptrace;
            sys_b = __NR_clone;
            sys_c = __NR_wait4;
            break;
        }
    }

    puts("You're all set! Ready for the adventure?");
    printf("\n");

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 0, 11),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, rand(), 0, 4),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, instruction_pointer) + 4)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, rand(), 0, 2),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x1337, 4, 0),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, sys_a, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, sys_b, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, sys_c, 0, 1),

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)
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

void start_adventure(void *armor) {
    ((void (*)())armor)();
}

int main(){
    puts("Your spaceship is drifting alone in the void and is about to be scrapped!");
    puts("You must build an armor stronger than any before to protect yourself and abandon the ship immediately!");
    puts("But beware: think again and again before acting!");

    srand(time(NULL));

    initialize_workbench();

    void *armor = build_armor();

    choose_addon();

    start_adventure(armor);

    return 0;
}