PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=

BPF_PROG_NAME = systail
BPF_PROG_SOURCE = capture_the_bee.bpf.c
BPF_PROG_OBJECT = $(BPF_PROG_NAME).o

USER_PROG_NAME = systail
USER_PROG_SOURCE = capture_the_bee.c

SECRET = secret

CLANG ?= clang
CLANG_CFLAGS = -g -O2 -target bpf
GCC ?= gcc
GCC_CFLAGS = -O2
GCC_LDFLAGS = -lbpf

INSTALL_DIR = $(DESTDIR)$(BINDIR)/.honey

all: $(BPF_PROG_OBJECT) $(USER_PROG_NAME)

$(BPF_PROG_OBJECT): $(BPF_PROG_SOURCE)
        $(CLANG) $(CLANG_CFLAGS) -c $< -o $@

$(USER_PROG_NAME): $(USER_PROG_SOURCE) $(BPF_PROG_OBJECT)
        $(GCC) $(GCC_CFLAGS) $< -o $@ $(GCC_LDFLAGS)

install: all
        mkdir -p $(INSTALL_DIR)
        mv $(BPF_PROG_OBJECT) $(INSTALL_DIR)/
        mv $(USER_PROG_NAME) $(INSTALL_DIR)/
        mv $(SECRET) $(DESTDIR)/etc/.secret
clean:
        rm -f $(BPF_PROG_OBJECT) $(USER_PROG_NAME)

.PHONY: all clean install
