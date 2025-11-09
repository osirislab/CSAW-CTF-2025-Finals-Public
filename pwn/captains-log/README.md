# Captain's Log

## Category: Pwn

* The captain has been driving for such a long time. It's time to rest!
* Before going to bed, he gave you a task of correcting the error within the lengthy navigation log.
* Don't let the captain down!

## Difficulty: Medium

* This challenge is inspired by [V-tables](https://buddurid.me/2025/10/04/securinets-quals-2025#:~:text=.interactive()-,V%2Dtables,-source%20code%20%3A) from Securinets CTF Quals 2025.
* Players should be familiar with ARM aarch64 instruction set.
* Players should master the techniques of **house of apple 3** in aarch64 architecture.

## Time Spent

* 2 hours or so: For those without relevant experience in aarch64 architecture, collecting right gadgets to perform FSOP attack and writing shellcode can be very time-consuming.

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

* A docker container is required to run this Pwn challeng on `arm64` machines.
    ```bash
    docker build --platform linux/arm64 -t captains-log .
    docker run -p 21007:21007 --privileged captains-log
    ```

## Artifacts

* Only `chal` and `Dockerfile` can be provided to participants.
