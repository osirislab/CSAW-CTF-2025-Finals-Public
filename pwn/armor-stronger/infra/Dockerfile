FROM ubuntu@sha256:66460d557b25769b102175144d538d88219c077c678a49af4afca6fbfc1b5252

RUN apt-get update && apt-get install -y socat && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -ms /bin/sh armor
WORKDIR /home/armor

COPY ./chal ./
COPY ./flag.txt ./

RUN chown -R armor:armor /home/armor && \
    chmod 700 /home/armor && \
    chmod 500 /home/armor/chal && \
    chmod 400 /home/armor/flag.txt

EXPOSE 21000

USER armor

CMD ["socat", "-T60", "TCP-LISTEN:21000,reuseaddr,fork", "EXEC:/home/armor/chal"]