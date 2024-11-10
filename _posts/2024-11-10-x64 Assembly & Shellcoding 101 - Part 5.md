---
title:  "x64 Assembly & Shellcoding 101 - Part 5"
header:
  teaser: "/assets/images/asm_part5.png"
categories:
  - Shellcoding
  - Assembly
  - Debugging
tags:
  - Shellcoding
  - x64
  - x64dbg
  - '2024'
  - nasm
  - assembly
  - debugging
---

Well, you will all be happy to know I'm finally keeping my word and doing what I promised early on in the series...We're going to do the following today:

> (Our code will not contain any NULL values btw)

- Locate Kernel32 and collect **PE Export Table** info
- Dynamically Locate **GetProcAddress**
- Use the handle to GetProcAddress to locate the address for **LoadLibraryA**
- Use the handle to GetProcAddress to locate **ExitProcess**
- Use the handle to LoadLibraryA to load **user32.dll**
- Use the handle to user32.dll to locate the **address of MessageBoxA** within user32.dll using GetProcAddress
- Pop the messagebox (not a literal assembly pop operation 😅 )
- call ExitProcess to exit gracefully!

Before we dive in, I'd like to point out something I noticed while revisiting x64 assembly.  Maybe it's just me, but in reviewing the PE export table for Windows 11, it seems like the address of names index lines up with address of functions.  Such that, we don't need to resort to getting the ordinal using the address of names index any longer.  I could be mistaken, but I've tested this on Windows 11 on two separate machines and same outcome.  I skipped using the ordinal lookup entirely and had no issues just plugging in the index I retrieved from the address of names lookup into the address of functions lookup.  Food for thought.  Maybe that should be expounded on further by someone who knows way more about Windows internals than I do 😆  With that little thought out of the way, let's carry on shall we?

Today's code will be the most challenging yet in the series, so fair warning.  There's a lot going on but I think you'll do just fine.  I'll break it down into sections, borrowing from the bullet points above.  

***Prologue - Locate Kernel32 and collect PE Export Table info***
-
```nasm
;nasm -fwin64 [x64findkernel32.asm]
;ld -m i386pep -o x64findkernel32.exe x64findkernel32.obj
BITS 64
SECTION .text
global main
main:
sub rsp, 0x28
and rsp, 0xFFFFFFFFFFFFFFF0
xor rcx, rcx                      ; RCX = 0
mov rax, [gs:rcx + 0x60]          ; RAX = PEB
mov rax, [rax + 0x18]             ; RAX = PEB->Ldr
mov rsi,[rax+0x10]                ; PEB.Ldr->InMemOrderModuleList
mov rsi, [rsi]
mov rsi,[rsi]
mov rbx, [rsi+0x30]               ; kernel32.dll base address
mov r8, rbx                       ; mov kernel32.dll base addr into r8
xor rcx, rcx                      ; Avoid null bytes from mov edx,[rbx+0x88] by using rcx register to add
add cx, 0x88ff
shr rcx, 0x8                      ; RCX = 0x88ff --> 0x88
mov edx, [rbx+rcx]                ; EDX = [&NewEXEHeader + Offset RVA ExportTable] = RVA ExportTable
add rdx, r8                       ; RDX = kernel32.dll + RVA ExportTable = ExportTable Address
mov r10d, [rdx+0x14]              ; Number of functions
xor r11, r11                      ; Zero R11 before use
mov r11d, [rdx+0x20]              ; AddressOfNames RVA
add r11, r8                       ; AddressOfNames VMA
mov rcx, r10                      ; store number of functions for future use
```

***Dynamically Locating GetProcAddress***
-
```nasm
mov rax, 0x9090737365726464       ; 'ddress'
shl rax, 0x10                     ; 7373657264640000
shr rax, 0x10                     ; 0000737365726464 terminate our string w/ no nulls present in our shellcode!
push rax
mov rax, 0x41636F7250746547       ; GetProcA 
push rax
mov rax, rsp	
kernel32findfunction:             ; Loop over Export Address Table to find WinApi names
    jecxz FunctionNameNotFound    ; Loop around this function until we find WinExec
    xor ebx,ebx                   ; Zero EBX for use
    mov ebx, [r11+rcx*4]          ; EBX = RVA for first AddressOfName
    add rbx, r8                   ; RBX = Function name VMA / add kernel32 base address to RVA and get WinApi name
    dec rcx                       ; Decrement our loop by one, this goes from Z to A
    ; Load first 8 bytes of "LoadLibrary"
    mov r9, qword [rax]           ; R9 = "GetProcA"
    cmp [rbx], r9                 ; Compare first 8 bytes
    jnz kernel32findfunction      ; If not equal, continue loop
    ; Check next part for "aryA" (4 bytes)
    mov r9d, dword [rax + 8]      ; R9 = "ddress"
    cmp [rbx + 8], r9d            ; Compare remaining part
    jz FunctionNameFound          ; If match, function found
	jnz kernel32findfunction
FunctionNameNotFound:
    int3
FunctionNameFound:
    push rcx
    pop r15                       ; getprocaddress position
    inc r15   
    xor r11, r11
    mov r11d, [rdx+0x1c]          ; AddressOfFunctions RVA
    add r11, r8                   ; AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
    mov eax, [r11+r15*4]          ; Get the function RVA.
    add rax, r8                   ; Found the GetProcAddress WinApi!!!
    push rax                      ; push GetProcAddress temporarily to be used by next segment
```

I really wish it didn't take so many lines of code to dynamically locate kernel32 + your initial API, but it's been this way for a long time it seems.  Thankfully, the other sections of code are much shorter and easier to follow, at least in my opinion. 😸

***Locate the address for LoadLibraryA using GetProcAddress handle***
-
```nasm
; Prepare arguments for getting handle to LoadLibraryA:
    pop r15                        ; temporary use
    mov r12, r15                   ; save copy of GetProcAddress for future use
    mov rdi, r8                    ; make a copy of kernel32 base address for future use
    mov rcx, r8                    ; RCX = handle to kernel32.dll (first argument)
; Load "LoadLibraryA" onto the stack
    mov rax, 0x41797261            ; aryA
    push rax
    mov rax, 0x7262694C64616F4C    ; LoadLibr 
    push rax
    mov rdx, rsp	                 ; RDX points to "LoadLibraryA" (second argument)
    sub rsp, 0x30                  ; decimal 48 ( 3 x 16 bytes)
    call r15                       ; Call GetProcAddress
    add rsp, 0x30                  ; alignmnent/shadow space adjustments
    mov r15, rax                   ; holds LoadLibraryA!
```
***Locate the address for ExitProcess using GetProcAddress handle***
-
```nasm
;getexitprocess
    mov r14, r12                    ; temporary assignment of GetProcess handle
    mov rcx, rdi                    ; RCX = handle to kernel32.dll (first argument)
; Load "ExitProcess" onto the stack
    mov rax, 0x90737365             ; 'ess'
    shl eax, 0x8                    ; 0000000073736500
    shr eax, 0x8                    ; 0000000000737365 terminate our string w/ no nulls present in our shellcode!
    push rax
    mov rax, 0x636F725074697845     ; ExitProc 
    push rax
    mov rdx, rsp	                  ; RDX points to "ExitProcess" (second argument)
    sub rsp, 0x30
    call r14                        ; Call GetProcAddress
    add rsp, 0x30
    mov r14, rax                    ; holds ExitProcess!
```
***Locate user32.dll using LoadLibraryA handle***
-
```nasm
;locate user32.dll
    mov rax, 0x90906C6C             ; add "ll" string to RAX
    shl eax, 0x10                   ; 000000006C6C0000
    shr eax, 0x10                   ; 0000000000006C6C
    push rax                        ; push RAX to stack
    mov rax, 0x642E323372657375     ; Add "user32.d" string to RAX.
    push rax                        ; Push RAX to stack
    mov rcx, rsp                    ; Move a pointer to User32.dll into RCX.
    sub rsp, 0x30
    call r15                        ; Call LoadLibraryA("user32.dll")
    mov rdi, rax                    ; holds User32.dll address
```
***Locate MessageBoxA address using user32.dll handle + GetProcAddress***
-
```nasm
; Prepare arguments for GetProcAddress for MessageBoxA:
    mov rcx, rdi                    ; RCX = handle to user32.dll (first argument)
    mov rax, 0x9041786F             ; Load "oxA" into RAX
    shl eax, 0x8                    ; 0000000041786F00
    shr eax, 0x8                    ; 000000000041786F
    push rax
    mov rax, 0x426567617373654D     ; Load "MessageB" into RAX                  
    push rax
    mov rdx, rsp                    ; RDX points to "MessageBoxA" (second argument)
    sub rsp, 0x30
    call r12                        ; Call GetProcAddress
    mov r15, rax                    ; store MessageBoxA
```
***Pop the MessageBox!***
-
```nasm
;messageboxfinally: 
    xor rcx, rcx                    ; hWnd = NULL (no owner window)
    mov rax, 0x9090906D             ; m, 0
	  shl eax, 24                     ; 000000006D000000
    shr eax, 24                     ; 000000000000006D
    push rax
    mov rax, 0x3374737973743367     ; g3tsyst3
    push rax
    mov rdx, rsp                    ; lpText = pointer to message
    mov r8, rsp                     ; lpCaption = pointer to title
    xor r9d, r9d                    ; uType = MB_OK (OK button only)
    sub rsp, 0x30
    call r15                        ; Call MessageBoxA
    add rsp, 0x30
```
***Call ExitProcess***
-
```nasm
;exitcleanly:
    xor ecx, ecx
    call r14                        ;ExitProcess
```

That's it!  Okay, now let's go ahead and get our shellcode/machine code:
![image](https://github.com/user-attachments/assets/eb4383b2-922d-470f-96fc-c007798c2325)

```c++
unsigned char shellcode[] =
"\x48\x83\xec\x28\x48\x83\xe4\xf0\x48\x31\xc9\x65\x48\x8b\x41\x60\x48\x8b\x40\x18\x48\x8b"
"\x70\x10\x48\x8b\x36\x48\x8b\x36\x48\x8b\x5e\x30\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48"
"\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x44\x8b\x52\x14\x4d"
"\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4c\x89\xd1\x48\xb8\x64\x64\x72\x65\x73\x73\x90\x90"
"\x48\xc1\xe0\x10\x48\xc1\xe8\x10\x50\x48\xb8\x47\x65\x74\x50\x72\x6f\x63\x41\x50\x48\x89"
"\xe0\x67\xe3\x20\x31\xdb\x41\x8b\x1c\x8b\x4c\x01\xc3\x48\xff\xc9\x4c\x8b\x08\x4c\x39\x0b"
"\x75\xe9\x44\x8b\x48\x08\x44\x39\x4b\x08\x74\x03\x75\xdd\xcc\x51\x41\x5f\x49\xff\xc7\x4d"
"\x31\xdb\x44\x8b\x5a\x1c\x4d\x01\xc3\x43\x8b\x04\xbb\x4c\x01\xc0\x50\x41\x5f\x4d\x89\xfc"
"\x4c\x89\xc7\x4c\x89\xc1\xb8\x61\x72\x79\x41\x50\x48\xb8\x4c\x6f\x61\x64\x4c\x69\x62\x72"
"\x50\x48\x89\xe2\x48\x83\xec\x30\x41\xff\xd7\x48\x83\xc4\x30\x49\x89\xc7\x4d\x89\xe6\x48"
"\x89\xf9\xb8\x65\x73\x73\x90\xc1\xe0\x08\xc1\xe8\x08\x50\x48\xb8\x45\x78\x69\x74\x50\x72"
"\x6f\x63\x50\x48\x89\xe2\x48\x83\xec\x30\x41\xff\xd6\x48\x83\xc4\x30\x49\x89\xc6\xb8\x6c"
"\x6c\x90\x90\xc1\xe0\x10\xc1\xe8\x10\x50\x48\xb8\x75\x73\x65\x72\x33\x32\x2e\x64\x50\x48"
"\x89\xe1\x48\x83\xec\x30\x41\xff\xd7\x48\x89\xc7\x48\x89\xf9\xb8\x6f\x78\x41\x90\xc1\xe0"
"\x08\xc1\xe8\x08\x50\x48\xb8\x4d\x65\x73\x73\x61\x67\x65\x42\x50\x48\x89\xe2\x48\x83\xec"
"\x30\x41\xff\xd4\x49\x89\xc7\x48\x31\xc9\xb8\x6d\x90\x90\x90\xc1\xe0\x18\xc1\xe8\x18\x50"
"\x48\xb8\x67\x33\x74\x73\x79\x73\x74\x33\x50\x48\x89\xe2\x49\x89\xe0\x45\x31\xc9\x48\x83"
"\xec\x30\x41\xff\xd7\x48\x83\xc4\x30\x31\xc9\x41\xff\xd6";
```

**And the c++ program itself:**

```c++
#include <windows.h>
#include <iostream>

// Shellcode (as given, formatted for clarity)
unsigned char shellcode[] =
"\x48\x83\xec\x28\x48\x83\xe4\xf0\x48\x31\xc9\x65\x48\x8b\x41\x60\x48\x8b\x40\x18\x48\x8b"
"\x70\x10\x48\x8b\x36\x48\x8b\x36\x48\x8b\x5e\x30\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48"
"\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x44\x8b\x52\x14\x4d"
"\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4c\x89\xd1\x48\xb8\x64\x64\x72\x65\x73\x73\x90\x90"
"\x48\xc1\xe0\x10\x48\xc1\xe8\x10\x50\x48\xb8\x47\x65\x74\x50\x72\x6f\x63\x41\x50\x48\x89"
"\xe0\x67\xe3\x20\x31\xdb\x41\x8b\x1c\x8b\x4c\x01\xc3\x48\xff\xc9\x4c\x8b\x08\x4c\x39\x0b"
"\x75\xe9\x44\x8b\x48\x08\x44\x39\x4b\x08\x74\x03\x75\xdd\xcc\x51\x41\x5f\x49\xff\xc7\x4d"
"\x31\xdb\x44\x8b\x5a\x1c\x4d\x01\xc3\x43\x8b\x04\xbb\x4c\x01\xc0\x50\x41\x5f\x4d\x89\xfc"
"\x4c\x89\xc7\x4c\x89\xc1\xb8\x61\x72\x79\x41\x50\x48\xb8\x4c\x6f\x61\x64\x4c\x69\x62\x72"
"\x50\x48\x89\xe2\x48\x83\xec\x30\x41\xff\xd7\x48\x83\xc4\x30\x49\x89\xc7\x4d\x89\xe6\x48"
"\x89\xf9\xb8\x65\x73\x73\x90\xc1\xe0\x08\xc1\xe8\x08\x50\x48\xb8\x45\x78\x69\x74\x50\x72"
"\x6f\x63\x50\x48\x89\xe2\x48\x83\xec\x30\x41\xff\xd6\x48\x83\xc4\x30\x49\x89\xc6\xb8\x6c"
"\x6c\x90\x90\xc1\xe0\x10\xc1\xe8\x10\x50\x48\xb8\x75\x73\x65\x72\x33\x32\x2e\x64\x50\x48"
"\x89\xe1\x48\x83\xec\x30\x41\xff\xd7\x48\x89\xc7\x48\x89\xf9\xb8\x6f\x78\x41\x90\xc1\xe0"
"\x08\xc1\xe8\x08\x50\x48\xb8\x4d\x65\x73\x73\x61\x67\x65\x42\x50\x48\x89\xe2\x48\x83\xec"
"\x30\x41\xff\xd4\x49\x89\xc7\x48\x31\xc9\xb8\x6d\x90\x90\x90\xc1\xe0\x18\xc1\xe8\x18\x50"
"\x48\xb8\x67\x33\x74\x73\x79\x73\x74\x33\x50\x48\x89\xe2\x49\x89\xe0\x45\x31\xc9\x48\x83"
"\xec\x30\x41\xff\xd7\x48\x83\xc4\x30\x31\xc9\x41\xff\xd6";


int main() {
    // Allocate executable memory
    void* exec_mem = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (exec_mem == nullptr) {
        std::cerr << "Memory allocation failed\n";
        return -1;
    }

    // Copy shellcode to the allocated memory
    memcpy(exec_mem, shellcode, sizeof(shellcode));

    // Create a function pointer to the shellcode
    auto shellcode_func = reinterpret_cast<void(*)()>(exec_mem);

    // Execute the shellcode
    shellcode_func();

    // Free the allocated memory
    VirtualFree(exec_mem, 0, MEM_RELEASE);

    return 0;
}
```

![image](https://github.com/user-attachments/assets/03c29f3c-80e3-4124-b750-d2550665b2d2)

While it may seem like an unnecessarily large amount of code, it's not too bad in the grand scheme of things.  I'm showing 132 total lines of code in Notepad++.
If we didn't have to account for nulls it would be a lot less.  But, this is not bad at all for how much is required to load a message box 😸  But it sure does feel good once it all comes together.  Next up will be sockets and a reverse shell! Stay tuned and thanks for reading.  I really do appreciate the support I receive and questions that arise from these posts.  Keep em' coming, and see ya soon!
