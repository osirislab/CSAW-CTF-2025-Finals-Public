FROM ubuntu@sha256:66460d557b25769b102175144d538d88219c077c678a49af4afca6fbfc1b5252 AS builder

FROM pwn.red/jail:latest

COPY --from=builder / /srv

COPY ./chal /srv/app/run
COPY ./flag.txt /srv/app/

RUN chmod 755 /srv/app/run

EXPOSE 21007

ENV JAIL_PORT=21007