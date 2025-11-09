# Armor Stronger

## Category: Pwn

* Your spaceship is drifting alone in the void and is about to be scrapped!
* You must build an armor stronger than any before to protect yourself and then abandon the ship immediately!
* But beware: think again and again before acting!

## Difficulty: Hard

* This challenge is inspired by [canon_event](https://github.com/TheRomanXpl0it/TRX-CTF-2025/tree/main/pwn/canon_event) from TRXCTF 2025.
* Players should be familiar with ARM aarch64 instruction set and be proficient in writing shellcode in aarch64 architecture.
* Players should have a basic knowledge of how `seccomp` works.
* Players should fully understand the mechanisms of `ptrace` syscall and `wait4` syscall.
* Additional notice for `arm64`: `clone` system call, `brk` instruction, and `iovec` structure.

## Time Spent

* 3 hours or so: For those without relevant experience, flexibly utilizing `ptrace` syscall, `clone` syscall, and `wait4` syscall to write shellcode in aarch64 architecture can be very time-consuming.

## Tools

* Binary Ninja or IDA to inspect the binary file
* GDB with gef or pwndbg to debug the binary file
* Python pwntools to write a solution script

## Infrastructure

* A docker container with an `linux/arm64` image of `ubuntu@sha256:66460d557b25769b102175144d538d88219c077c678a49af4afca6fbfc1b5252` is required to compile C source code of this Pwn challenge to binary on `arm64` machines.
    ```bash
    gcc \
        -fstack-protector-strong \
        -fPIE -pie \
        -Wl,-z,relro,-z,now \
        -s \
        -o chal \
        main.c
    ```

* A docker container is required to run this Pwn challenge on `arm64` machines.
    ```bash
    docker build --platform linux/arm64 -t armor-stronger .
    docker run -p 21000:21000 armor-stronger
    ```

## Artifacts

* **Only** `chal`, `Dockerfile`, and `main.c` can be provided to participants.
