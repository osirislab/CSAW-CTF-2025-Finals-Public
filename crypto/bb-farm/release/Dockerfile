FROM rust:1.89 AS runtime-libs

FROM pwn.red/jail

RUN mkdir -p /srv/app \
    && mkdir -p /srv/lib/x86_64-linux-gnu \
    && mkdir -p /srv/lib64 \
    && mkdir -p /srv/bin

COPY --from=runtime-libs /lib/x86_64-linux-gnu /srv/lib/x86_64-linux-gnu
COPY --from=runtime-libs /lib64 /srv/lib64
COPY --from=runtime-libs /bin /srv/bin

COPY bb-farm /srv/app/run
COPY artifacts /srv/app/artifacts

ENV JAIL_TIME 300
ENV JAIL_PIDS	0
ENV JAIL_MEM 100M
