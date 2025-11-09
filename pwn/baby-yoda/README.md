# Baby Yoda

## Category: Pwn

* A long time ago in a galaxy far, far away...
* The Baby Yoda has been hungry for long.
* Let it hold on until the Mandalorian comes to pick it up.

## Difficulty: Medium

* Players should be familiar with MIPS64 rel2 instruction set.
* Players should master the techniques of **ROP** and **stack pivoting** in mips64el architecture.

## Time Spent

* 2 hours or so: For those without relevant experience in mips64el architecture, stack pivoting with ROP chain can be very time-consuming.

## Tools

* Binary Ninja or IDA to inspect the binary file
* GDB with gef or pwndbg to debug the binary file
* Python pwntools to write a solution script

## Infrastructure

* A docker container with an `linux/amd64` image of `ubuntu@sha256:66460d557b25769b102175144d538d88219c077c678a49af4afca6fbfc1b5252` is required to compile C source code of this Pwn challenge to binary.
    ```bash
    apt install gcc-mips64el-linux-gnuabi64
    mips64el-linux-gnuabi64-gcc \
        -march=mips64r2 -mabi=64 \
        -fno-stack-protector \
        -fPIE -pie \
        -Wl,-z,noexecstack,-z,relro,-z,now \
        -o chal \
        main.c
    ```

* A docker container is required to run this Pwn challenge.
    ```bash
    docker build --platform linux/amd64 -t baby-yoda .
    docker run -p 21004:21004 --privileged baby-yoda
    ```

* Reference: https://github.com/Legoclones/mips-pwn-research-resources

## Artifacts

* Only `chal`, `Dockerfile`, and `qemu-mips64el` can be provided to participants.
