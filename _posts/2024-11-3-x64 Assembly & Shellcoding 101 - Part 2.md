---
title:  "x64 Assembly & Shellcoding 101 - Part 2"
header:
  teaser: "/assets/images/pestuff.png"
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

Okay, I lied 😄  I thought I'd use part 2 to discuss removing NULL bytes, and that's going to happen I promise!  But I had some good feedback from the first part of the x64 shellcode and assembly post and some questions regarding calculating PE offsets.  So, I wanted to use Part 2 to explain how I arrived at the specific offsets I used in my code.  Here goes!

First let’s get a decent PE viewer.  I’m using Pepper as my PE viewer of choice for viewing x64 binaries:
[Pepper x64 PE Viewer](https://github.com/jovibor/Pepper)

I’ll walk through each part of the PE header an exports section. Let’s use the assembly code from the blog as our guide:
```nasm
mov r8, rbx         ; mov kernel32.dll base addr into r8
```
Kernel32 base address in my case is: **00007FFA63570000**

So, 00007FFA63570000 is now in r8 and rbx
```nasm
mov ebx, [rbx+0x3C] (move into lower 32 bits of the rbx register, hence why we use ebx)
```
Our x64dbg debugger would show: **dword ptr ds:[rbx+3C]=[kernel32.00007FFA6357003C]=F8**

This is our PE signature offset, as seen in the image below.  We first get the value pointed to by kernel32.00007FFA6357003C, which is F8, and then we add that to kernel32
![image](https://github.com/user-attachments/assets/f93328c0-35b0-42a7-ab74-ec6beea7fd9c)
```nasm
add rbx, r8 = 00007FFA635700F8 (PE header/DOS header)
```
Now, we’re in [IMAGE_OPTIONAL_HEADER64]
[IMAGE_DATA_DIRECTORY]
```nasm
mov edx, [rbx+0x88]
```
This is to get the offset to our export table
![image](https://github.com/user-attachments/assets/d20101bb-943b-417c-8c67-8bf5bf53246d)

**F8 + 0x88 = 180**
Which equals **00000000000A3D80** for me, which is the RVA for the EXPORT TABLE
```nasm
add rdx, r8
```
**00007FFA63613D80** → address of RVA EXPORT TABLE
```nasm
mov r10d, [rdx+0x14]          ; r10d (the lower 32 bits of r10) now holds the function count.
```
![image](https://github.com/user-attachments/assets/4166c74d-0d1a-4320-bacb-d65e62bd69cd)
```nasm
xor r11, r11                  ; Zero R11 before use
```
```nasm
mov r11d, [rdx+0x20]          ; r11d (the lower 32 bits of r11) now holds the AddressOfNames RVA
```
**00000000000A5814** in x64dbg
![image](https://github.com/user-attachments/assets/14a48b31-c9e5-4cfb-bb61-37a91d853d74)
```nasm
add r11, r8                   ; AddressOfNames VMA
```
**00007FFA63615814**
```nasm
mov rcx, r10                      ; r10 has our total function count.  Set RCX loop counter
```
**; Loop over Export Address of Names Table to find WinApi names**
```nasm
kernel32findfunction: 
               
    mov ebx, [r11+rcx*4]                 ; EBX = RVA for first AddressOfName
```

**For the instruction above, we’re using:**

+ r11 = RVA of function names

+ \+ rcx = the place in the function list
 
+ \* 4 =  rcx * 4: Since each RVA in AddressOfNames is a 4-byte entry, multiplying rcx by 4 gives the correct offset to retrieve the RVA of a specific function name. 

**Once the loop finishes, our function name will have been found and the location in the function names will be stored in rcx**

**We push rcx then pop it into r15, which leads us here:**

```nasm
OrdinalLookupSetup:  ;We found our target WinApi position in the functions lookup
   pop r15           ;Winexec position
   js OrdinalLookup
   
OrdinalLookup:   
mov rcx, r15                        ;Winexec location in function names
xor r11, r11                        ;clear r11
mov r11d, [rdx+0x24]                ; AddressOfNameOrdinals RVA
```

**X64dbg output = dword ptr ds:[rdx+24]=[kernel32.00007FFA63613DA4]=A7280**
![image](https://github.com/user-attachments/assets/311dbfd0-8fb2-40da-b194-568fe652d090)
```nasm
add r11, r8                   ; AddressOfNameOrdinals VMA
```
**Add to kernel32 = 00007FFA63617280**
```nasm
; Get the function ordinal from AddressOfNameOrdinals
inc rcx
mov r13w, [r11+rcx*2]         ; AddressOfNameOrdinals + Counter. RCX = counter
```
**Virtual memory address + rcx (1612) * 2 (bytes) = ordinal value for WinExec!!!**
![image](https://github.com/user-attachments/assets/4a84140b-b393-4f75-a862-fa5b864cd242)

```nasm
;With the function ordinal value, we can finally lookup the WinExec address from AddressOfFunctions.
; Get function address from AddressOfFunctions
xor r11, r11                           ; clear r11
mov r11d, [rdx+0x1c]          ; AddressOfFunctions RVA
```
![image](https://github.com/user-attachments/assets/a6941209-e28a-4a0d-b4ec-b159adfbbde7)
```nasm
add r11, r8                   ; AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
mov eax, [r11+r13*4]        ; Get the function RVA.
```

**R11 = Relative Virtual memory address**

**R13 = Winexec ordinal (0x64C = 1612 decimal)**

**\* 4 (bytes) = 1612  = Winexec**

**X64dbg = dword ptr ds:[r11+r13*4]=[kernel32.00007FFA636156D8]=608B0**
![image](https://github.com/user-attachments/assets/73c50ad3-bd92-46cd-9208-b5f86dea6339)

```nasm
add rax, r8                   ; Found the WinExec WinApi!!!
```

**Add kernel32 to our RVA of WinExec**
![image](https://github.com/user-attachments/assets/5bab1287-91bb-46f8-8bf0-809b6e9cb2ef)

**RAX now hold the actual address for WinExec!!!**

That’s it!  Now you can use Winexec to your liking and you should also have a better idea how to walk the PE and parse PE headers, explore the export directory info, etc.  Thanks!
