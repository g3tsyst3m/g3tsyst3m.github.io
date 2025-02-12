---
title:  "Buffer Overflows on Win11 x64 fully patched w/ROP gadgets and ASLR Bypass"
permalink: /drafts/my-draft/
published: false
header:
  teaser: "/assets/images/asm_part6.png"
categories:
  - Buffer Overflow
  - ASLR Bypass
  - Rop Gadgets
tags:
  - Shellcoding
  - Buffer Overflow
  - Binary Exploitation
  - x64
  - x64dbg
  - '2025'
  - ASLR bypass
  - ROP gadgets
  - nasm
  - assembly
  - debugging
---

Okay, I'll be honest.  I've spent the last month preparing this writeup 😺 I thought to myself,"How much effort could it possibly be to refresh my memory on buffer overflows on a modern Windows x64 OS?"  **My conclusion**: Wow...Windows 11 x64, fully updated, is impressively fortified against modern Buffer Overflow attacks.  Like, very resilient in fact.  The last time I dabbled in buffer overflows I was using Windows 10 and it was so simple.  Basically, toss some x86 shellcode at a vulnerable program and let the stack handle the rest.  For the longest time, the stack was executable by default.  Apart from locating non-ASLR modules, it was a breeze to carry out these type of exploitations, and this wasn't that long ago.  My have times changed...the stack is NOT executable on Windows 11.  In fact, most modern BIOS settings have secure boot enabled and stack execution is not possible, even if you make it executable with VirtualProtect API, etc.

Jumping ahead to 2025, we've got a lot of work ahead of us.  Let's start by identifying what you'll need to follow along with this writeup:  

- Intermediate understanding of x64 assembly (I have a course you can follow if you need to brush up 😙 )
- **GCC** for compiling C/C++ code on Linux; I use Debian or Manjaro almost interchangeably.  You can compile the source code I use using Visual Studio just as well, but I find gcc on linux to be easier.  Especially for compiling with parameters such as turning off ASLR, etc
- **x64dbg** - My debugger of choice.  Feel free to use **WinDbg** if you are more comfortable, but I like x64dbg for its simplicity and minimal learning curve
- **Python3** - Python will be used for carrying out our payload for the buffer overflow against the vulnerable .exe

Next, we will want to ensure all exploit protection is enabled because we want to prove to the world how **l33t** we actually are 😸 I have the following enabled on my PC, which is every exploit and memory protection module I know of that we can enable on a fully patched, Windows 11 x64 machine.  I also have secureboot enabled in my BIOS:

![image](https://github.com/user-attachments/assets/1daf3f1a-8925-4aa8-9269-c7de119a9cf4)
![image](https://github.com/user-attachments/assets/d6cc86a4-61c6-435f-8e60-ace28243074a)
![image](https://github.com/user-attachments/assets/4b9097b1-ac62-4006-b737-00bf49edffd5)

Cool, now we need to understand ASLR, DEP, and ROP gadgets.  

***Let's learn about ASLR, DEP, and ROP Gadgets!***
-
> **What is ASLR (Address Space Layout Randomization)?**

**Address Space Layout Randomization (ASLR)** is a security technique used to randomize the memory addresses used by system processes and applications. The goal of ASLR is to make it more difficult for attackers to predict the memory layout of a process, particularly where key components such as libraries, stack, heap, and other buffers reside. This randomization makes it harder to exploit buffer overflow vulnerabilities,  since we the attacker would not be able to inject malicious code into a known memory address.

> **What Are ROP Gadgets?**
**Return-Oriented Programming (ROP) gadgets** are small chunks of assembly code that already exist within our program or library loaded into memory. These gadgets typically end in a "return" instruction, which is why they're called ROP gadgets. By chaining these gadgets together, we are able to craft a payload that performs malicious actions without ever needing to inject our own code into memory. This is imperative today as memory is non-executable (like with DEP—Data Execution Prevention), as ROP allows attackers to reuse existing code to carry out their exploit.

> **Why ASLR is Not Foolproof**
While ASLR significantly increases the difficulty of executing attacks, it is not foolproof. A key reason is that ASLR may only randomize the higher bits of the memory address, leaving the lower bits predictable. On Windows, it’s common for ASLR to randomize only the upper half of the address, particularly for user-space processes, while leaving the lower half static. We will be taking advantage of this "flaw" by the way 😸  So in other words, this can make it possible for us to bypass ASLR by exploiting known offsets which we can determine in advance using tools such as `Ropper`, which I will explain in greater detail later on in the post. 

The Need for ROP Gadgets
We need to use ROP gadgets because modern defenses like DEP (Data Execution Prevention) and ASLR prevent traditional buffer overflow attacks that inject code directly into memory. With DEP enabled, code execution is blocked on regions marked as non-executable, such as the stack or heap. Since ROP uses existing code, it avoids the need to inject new code into a vulnerable program.

By chaining ROP gadgets together, attackers can carry out complex exploits like returning to a function pointer to take control of program execution flow, bypassing defenses that block direct code injection.

Why We Can’t Modify the Stack with VirtualProtect on Modern Windows (Secure Boot & Windows 11)
The stack is typically marked as non-executable in modern systems, a feature designed to prevent traditional exploits that inject shellcode into the stack and execute it. On systems with Secure Boot (which is enabled on most Windows 11 machines), the integrity of the boot process and critical system components is protected to prevent unauthorized code execution.

Because of these protections, even if you attempt to change the memory protection of the stack using VirtualProtect (a Windows API that allows changing memory access permissions), the system will block such attempts if it's running under Secure Boot. This is because the system ensures that any changes to executable memory, particularly stack memory, are controlled and do not come from malicious sources.

With the stack marked as non-executable, attacks must instead rely on ROP gadgets in executable memory regions (such as shared libraries or other parts of the application’s memory) to craft a malicious payload. The combination of Secure Boot, DEP, and ASLR increases the complexity of executing successful exploits, but skilled attackers can still chain ROP gadgets and bypass these protections if they have enough knowledge of the program’s memory layout.

Now on to the the fun part.  Let's kick off the source code for the application we will intentionally make vulnerable to a buffer overflow exploit, and also include some code to allow for assistance with ROP gadgets which I'll soon explain in greater detail.

```cpp
#include <windows.h>
#include <iostream>
#include <cstring>

//compilation instructions on mingw32/gcc
//x86_64-w64-mingw32-g++ -o overflow.exe overflow.cpp -fno-stack-protector -no-pie

// Disable security features to make the program vulnerable if using Visual Studio 
#pragma comment(linker, "/SAFESEH:NO") // Disable SafeSEH
#pragma comment(linker, "/DYNAMICBASE:NO") // Disable ASLR
#pragma comment(linker, "/NXCOMPAT:NO") // Disable DEP


void win_function() {
    std::cout << "You have successfully exploited the program!\n";
    system("calc.exe"); // Launch calculator as a demonstration
}


void vulnerable_function() {
    char buffer[275]; // medium-size buffer for the overflow
    std::cout << "Enter some input: ";
    std::cin >> buffer; // Unsafe function vulnerable to overflow
}

int main() {
    LPVOID allocatedMemory = VirtualAlloc(
        NULL,  // Address, NULL means it is chosen by the system
        1024,  // Size in bytes
        MEM_COMMIT | MEM_RESERVE, // Allocation type
        PAGE_READWRITE // Memory protection
    );

    if (allocatedMemory != NULL) {
        printf("Memory allocated at %p\n", allocatedMemory);
    } else {
        printf("VirtualAlloc failed with error code %lu\n", GetLastError());
    }
    std::cout << "Welcome to the vulnerable program!\n";
    vulnerable_function();
    std::cout << "Goodbye!\n";
    return 0;
}
```

Let's talk through the code for a moment.  The first function is easy enough to understand. It simply spawns a calculator and can only be reached by performing a successful buffer overflow.  We intentionally do not call this function anywhere in the code because step 1 of this buffer overflow writeup is to execute this calculator by exploiting the vulnerable buffer.

```cpp
void win_function() {
    std::cout << "You have successfully exploited the program!\n";
    system("calc.exe"); // Launch calculator as a demonstration
}
```

Next up, we have the vulnerable buffer itself.  I assigned it 275 bytes because I want to have enough room for our shellcode and ROP gadgets, which will make a lot more sense later on in this writeup.

```cpp
void vulnerable_function() {
    char buffer[275]; // medium-size buffer for the overflow
    std::cout << "Enter some input: ";
    std::cin >> buffer; // Unsafe function vulnerable to overflow
}
```

We will be overflowing the buffer with an input of 289 total bytes which will eventually include a NOP sled, our shellcode and ROP Gadgets. For now, we'll just use 
