---
title:  "ElevationStation - A walk through the development process [PART 1]"
header:
  teaser: "/assets/images/token.png"
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

Hello Infosec enthusiasts!  I want to finally provide a detailed overview of the concepts and functionality behind elevationstation.  
This tool came about from my own pursuits in learning more about managing windows tokens and how one can leverage more privileges by manipulating windows tokens

Where to begin?  I guess the initial drive came from trying to understand how one elevates their privileges using Metasploit's `getsystem` command.
I wanted to gain a deeper understanding in how this is carried out and draft my own code to accomplish the same thing.   
Interestingly enough, this led me down a path of learning / refreshing my memory on a number of things:

- Learning more about Windows API in general
- Learning how to escalate a user that is a member of the local admins group but not elevated using UAC bypass mock folder technique (more on this later)
- Learning how to fully use and understand process hacker/system informer
- Understanding the unique differences between spawning a shell with `CreateProcessAsUser` versus `CreateProcessWithToken`
- Learning how Metasploit spawns the elevated shell within the same console (this took me a while to understand for a number of reasons)

In short, I was once again inspired by Metasploit's getsystem functionality and that also inspired my twitter handle.  I'm a huge HD Moore fan too 😸

## Token Permissions

Within every logged in user's process list, you will find often work with primary and impersonation tokens.  
If the process handle contains a token, you can find it in the `Handles` section of System Informer (Process Hacker):
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/1079cf4a-f08f-4dc3-a8d2-3edfb78c0569)

You can also view Token information and Token type in the `Tokens` tab itself:
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/72007808-9834-4c3f-855c-475be1a49d47)

As an example, Let's enable the seDebug privilege to our own process first so we can access remote processes. ❗Important❗ You can NOT enable a privilege that does not exist within the process...yet 😄
I will show you a ways around that barrier later.  For now, just know that a process starts with certain token privileges and unless it is listed, you cannot enable a token privilege that doesn't exist within the process.

here's our process in question, and the privilege is listed!
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/c28ff122-4972-4cc6-8d45-24e4ae3eab58)

Next, let's enable it.  you can of course do this within processhacker/systeminformer itself but we will be doing it programatically.
The code for achieving this can be found below:
 
 ```cpp
void setProcessPrivs(LPCWSTR privname)
{
    //cin.get();
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE pToken;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        privname,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        Color(14);
        printf("[!] LookupPrivilegeValue error: %u\n", GetLastError());
        Color(7);
        exit(0);
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &pToken))
        printf("[+] opened process token!\n");

    if (!AdjustTokenPrivileges(pToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
    {
        Color(14);
        printf("[!] AdjustTokenPrivileges error: %u\n", GetLastError());
        Color(7);
        exit(0);
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        Color(14);
        printf("[!] The token does not have this specified privilege available to the process. \n");
        Color(7);
        exit(0);
    }
    Color(2);
    printf("[+] Privilege: %ws added successfully!!!\n", privname);
    Color(7);
    CloseHandle(pToken);
    std::cin.get();
}
```
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/767f2b58-bbbf-48f3-8870-ec5c1e4a10f6)
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/bcce17c9-330f-44b3-8d70-ef61bdac3aaf)

And just like that, our token permission has been granted!

That concludes Part 1 of this series explaining the thoughts and functionality behind ElevationStation. Until next time!
