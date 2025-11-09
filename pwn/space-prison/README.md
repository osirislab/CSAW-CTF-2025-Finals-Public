# Space Prison

## Category: Pwn

* In the cold silence of orbit lies a prison, the most heavily guarded penitentiary in space.
* Each cell is sealed within a military-class force field, reserved only for the most dangerous criminals.
* Is there a flaw in this impenetrable fortress? Well, that's for you to find out.

## Difficulty: Medium

* Players should be familiar with ARM aarch64 instruction set.
* Players should master the techniques of **large bin attack** and **house of apple** in aarch64 architecture.

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

* A docker container is required to run this Pwn challenge on `arm64` machines.
    ```bash
    docker build --platform linux/arm64 -t space-prison .
    docker run -p 21002:21002 --privileged space-prison
    ```

## Artifacts

* Only `chal` and `Dockerfile` can be provided to participants.
