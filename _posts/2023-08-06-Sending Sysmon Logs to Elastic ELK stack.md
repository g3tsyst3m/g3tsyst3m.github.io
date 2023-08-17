---
title:  "Sending Sysmon Logs to Elastic ELK stack"
header:
  teaser: "/assets/images/sysmon_example.png"
categories:
  - Threat Hunting
tags:
  - elk
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

Let's pickup where we left off.  If you haven't done so already, please do check out the previous writeup on how to setup Elastic Stack, Logstash, and Kibana (ELK).
Now that we have that prepared, let's go ahead and get started downloading and configuring files to prepare for sysmon log ingest!

first things first...we need to download and install sysmon 😸

**[Installing Sysmon]**
-

go here to grab it: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

then we need to install it and then add our config changes.  Feel free to change the config to your liking.

the config template I start with: 

```
  <Sysmon schemaversion="4.40">
  <HashAlgorithms>*</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <CreateRemoteThread onmatch="exclude"></CreateRemoteThread>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="exclude"></ImageLoad>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude"></ProcessCreate>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <FileCreateTime onmatch="include"></FileCreateTime>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="exclude"></NetworkConnect>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <ProcessTerminate onmatch="include"></ProcessTerminate>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <DriverLoad onmatch="exclude"></DriverLoad>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <RawAccessRead onmatch="include"></RawAccessRead>
    </RuleGroup> 
    <RuleGroup name="" groupRelation="or">
        <ProcessAccess onmatch="exclude">
    </ProcessAccess>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="exclude"></FileCreate>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include"></RegistryEvent>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <FileCreateStreamHash onmatch="exclude"></FileCreateStreamHash>
    </RuleGroup>
  <RuleGroup name="" groupRelation="or">
    <PipeEvent onmatch="exclude"></PipeEvent>
  </RuleGroup>
  <RuleGroup name="" groupRelation="or">
    <WmiEvent onmatch="exclude"></WmiEvent>
  </RuleGroup>
  <RuleGroup name="" groupRelation="or">
    <DnsQuery onmatch="exclude"></DnsQuery>
  </RuleGroup>
  <RuleGroup name="" groupRelation="or">
    <FileDelete onmatch="include"></FileDelete>
  </RuleGroup>
  </EventFiltering>
</Sysmon>
```

save as config.xml and then fire up sysmon!

`sysmon64.exe -accepteula –i config.xml -l -n` <-- -l and -n enables checking loaded modules and checking network connections 

`sysmon64.exe -c` <-- shows your current config

**[Installing Winlogbeat]**
-

https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.9.0-windows-x86_64.zip

download and extract it to the folder of your choosing:

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/247d0716-f89b-4e03-b4b1-892d03d302e5)

next, right click and edit winlogbeat.yml in your favorite Text editor:

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/1c5720bd-4a6d-4c69-ba3f-ff7c7695d471)

here are the changes you make (powershell logging optional):

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/b538b171-b368-447d-b872-238dc2d90ef6)

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/91c5b7c2-2abb-409f-82f9-bc09b7982a85) **<--use your server ip here**

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/d001383e-9136-44f2-be70-b6be8d4883d1) **<--use your server ip here**

Okay, almost done!  next, we need to go into powershell.  We will want to temporarily bypass the powershell Execution Policy so we can run scripts. 

`powershell -ExecutionPolicy Bypass`

next, we want to install the winlogbeat service:

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/73608fb2-e5b2-4f62-b337-34e51f43f3ba)

finally, start the service

`start-service winlogbeat`

Return to Kibana and check for new logs!!!

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/e3808a9d-852a-43a6-b9d8-cc2229822e52)

that's it!  Next time, we'll use Elastic to discover unwanted programs on our machine, combing through logs collected via sysmon! 😸 

I may also introduce a python program that uses pefile to scan executables for malicious windows api function imports and exports if I have time. See you then!

