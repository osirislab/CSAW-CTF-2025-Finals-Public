# Mrs. Negative

## Category: Pwn

* Mrs. Negative is the queen of an alien species, which has their own way of communicating.
* In order to promote communication between interstellar species, you are sent as an envoy.
* Try to understand what she's saying. Don't provoke her!

## Difficulty: Hard

* Players should fully understand the knowledge of `n132`'s [RetroverFlow](https://github.com/n132/RetroverFlow) focusing on the `memcpy` function.
* Players should master the techniques of `house of einherjar` and `unsafe unlink`.
* Players should know how to pop a shell through `__exit_funcs abuse` or `FSOP`.

## Time Spent

* 3 hours or so: This is a complicated heap challenge that involves multiple heap exploitation techniques.

## Tools

* Binary Ninja or IDA to inspect the binary file
* GDB with gef or pwndbg to debug the binary file
* Python pwntools to write a solution script

## Infrastructure

* A docker container with an `linux/amd64` image of `ubuntu@sha256:66460d557b25769b102175144d538d88219c077c678a49af4afca6fbfc1b5252` is required to compile C source code of this Pwn challenge to binary.
    ```bash
    gcc \
        -mavx2 -mno-avx512f \
        -fstack-protector-strong \
        -fPIE -pie \
        -Wl,-z,relro,-z,now \
        -s \
        -o chal \
        main.c
    ```

* A docker container is required to run this Pwn challenge.
    ```bash
    docker build --platform linux/amd64 -t mrs-negative .
    docker run -p 21003:21003 --privileged mrs-negative
    ```

## Artifacts

* Only `chal` and `Dockerfile` can be provided to participants.
