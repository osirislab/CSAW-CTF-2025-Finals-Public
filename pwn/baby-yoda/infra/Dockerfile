FROM ubuntu@sha256:66460d557b25769b102175144d538d88219c077c678a49af4afca6fbfc1b5252 AS builder

RUN apt-get update && apt-get install -y gcc-mips64el-linux-gnuabi64

FROM pwn.red/jail:latest

COPY --from=builder / /srv

COPY ./chal /srv/app/
COPY ./flag.txt /srv/app/
COPY ./qemu-mips64el /srv/app/
COPY ./run.sh /srv/app/run

RUN chmod 755 /srv/app/chal
RUN chmod 755 /srv/app/qemu-mips64el
RUN chmod 755 /srv/app/run

EXPOSE 21004

ENV JAIL_PORT=21004