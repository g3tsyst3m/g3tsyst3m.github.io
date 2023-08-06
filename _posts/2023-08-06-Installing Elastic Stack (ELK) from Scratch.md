---
title:  "Installing Elastic Stack (ELK) from Scratch"
header:
  teaser: "/assets/images/elastic.png"
categories:
  - Blue team
  - Threat Hunting
  - ElasticSearch
tags:
  - elk
  - elastic
  - kibana
  - logstash
  - filebeats
  - winlogbeat
  - sysmon
  - elevationstation
---

Hey there red team....I mean <span style="color:blue"> BLUE TEAM </span> cadet 😅 I don't just focus on red team stuff you know...and it's been long overdue that I do a writeup on not just red team tools, but more emphasis on blue team defensive measures/tools. Today, we learn how to install Elastic ELK stack from start to finish.  Well, let's get to it!

First off, I'm using Debian. You'll likely want to use either Debian or Ubuntu for your experience to most closely mimic mine.  We will need the following in order to successfully Install Elastic Stack 8 (ELK 8) on Debian:

**Version of Debian I'm using:**
-
root@debian:/usr/bin# lsb_release -a

No LSB modules are available.

Distributor ID:	Debian

Description:	Debian GNU/Linux 12 (bookworm)

Release:	12

Codename:	bookworm

**Resource Requirements:**
-
I use VirtualBox.  You can use whatever flavor of VM environment you like.

3 CPUs, 6.5 GB RAM (8GB ram is ideal)

50-75GB harddrive storage

OpenJDK/Oracle Java

root privileges

also worth mentioning is enabling your shared clipboard.  for VirtualBox, that's here:

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/aa5e3842-4f91-4380-a1c9-a0e13a76a376)

**Get all your packages up-to-date!!!**

`sudo apt update && sudo apt upgrade -y`

**Install Java**

Java must be installed before ELK can be used. I'm using the following version:

root@debian:/usr/bin# java --version

openjdk 17.0.8 2023-07-18

OpenJDK Runtime Environment (build 17.0.8+7-Debian-1deb12u1)

OpenJDK 64-Bit Server VM (build 17.0.8+7-Debian-1deb12u1, mixed mode, sharing)

`sudo apt install openjdk-17-jdk -y`

**Add Elastic Stack 8 Repositories**

(you'll want to switch to **root** user for this and all remaining steps)

`curl  -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/elastic.gpg`

`apt install apt-transport-https`

`echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-8.x.list`

now let's update our package index:

`apt update`

**Install Elastic Search!**
-

`apt install vim elasticsearch -y`

edit the config once it is finished installing:

`nano /etc/elasticsearch/elasticsearch.yml`

uncomment (remove the hash/pound sign # ) from the following lines in your config file:

`cluster.name: elkcluster-1`

`network.host: 0.0.0.0`

`http.port: 9200`

**save + quit**

now, create and edit this file: `nano /etc/elasticsearch/jvm.options.d/jvmconf.conf`

add the following inside the file:

`-Xms1g`
 
`-Xmx1g`

**save + quit**

restart elasticsearch and enable the service at startup

`sudo systemctl restart elasticsearch`

`sudo systemctl enable elasticsearch`

Reset the password of the elastic superuser:

`/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -i`

**check to make sure it's responding to our queries:**

`curl --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic https://localhost:9200`

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/9e90000b-360b-47f7-b0a1-1f7ae4cf5971)

**[Install Logstash]**
-

apt install logstash

**Setup logstash to listen for filebeat input:**

`nano /etc/logstash/conf.d/beats.conf`

```
input {
  beats {
    port => 5044
  }
}
filter {
  if [type] == "syslog" {
     grok {
        match => { "message" => "%{SYSLOGLINE}" }
  }
     date {
        match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
     }
  }
}
output {
  elasticsearch {
    hosts => ["https://127.0.0.1:9200"]
    user => "elastic"
    password => "[your elastic password here!!!]"
    ssl => true
    ssl_certificate_verification => false
    index => "logstash-%{+YYYY.MM.dd}"
    #index => "beats-%{+YYYY.MM}" } } 
 }
}
```

**start and enable logstash!**

`sudo systemctl start logstash`

`sudo systemctl enable logstash`

**[Install Kibana]**
-

`apt install kibana`

`nano /etc/kibana/kibana.yml`

**uncomment/edit the following:**

`server.port: 5601`

`server.host: "0.0.0.0"`

**comment out the following:**

\# =================== System: Elasticsearch ===================

\# The URLs of the Elasticsearch instances to use for all your queries.

`#elasticsearch.hosts: ["https://localhost:9200"]`

**add/uncomment this line:**

`elasticsearch.ssl.verificationMode: certificate`

**this part should be added for you automatically.  Adjust accordingly:**

`elasticsearch.hosts: ['https://192.168.1.50:9200']` <--I added in my server's IP

`elasticsearch.serviceAccountToken: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX` <-- your token should be here

**restart and enable kibana**

`systemctl restart kibana`

`systemctl enable kibana`

**[Install Filebeat]**
-

`apt install filebeat`

`nano /etc/filebeat/filebeat.yml`

make sure these lines look as follows:

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/8de1c84b-9a5e-45a4-b2cc-0ee3144559cd)

comment out the following:

`#-------------------------- Elasticsearch output ------------------------------`

`#output.elasticsearch:`

  `# Array of hosts to connect to.`
  
  `#hosts: ["localhost:9200"]`

  **enable logstash:**

`#----------------------------- Logstash output --------------------------------`

`output.logstash:`

  `# The Logstash hosts`
  
  `hosts: ["localhost:5044"]`
  
**Now, enable and restart filebeat!**
  
`systemctl enable filebeat`

`systemctl restart filebeat`

**Finalize Kibana**
-

**generate your Kibana enrollment token:**

`/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana`

Now open your browser and point it to http://localhost:5601 or http://your-server-ip:5601 if you set it to that, and enter your token:

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/5903e68c-0b18-4db4-a648-51bd598c7afb)

**now generate and paste in your verification code:**

`/usr/share/kibana/bin/kibana-verification-code`

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/a7869d2f-2106-414e-8008-03973e313556)

now let it finish finalizing everything:

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/77a3432c-4672-4c71-84c2-570c7ccb1790)

(this sometimes hangs at the "Completing Setup" part.  I'd just open another tab and browse to http://localhost:5601 to see if it finished)

Now browse to your Discover tab and you should see logs coming in!

![image](https://github.com/g3tsyst3m/g3tsyst3m.github.io/assets/19558280/5273083e-4bfc-4b2d-971d-e2a34c0f548e)

Stay tuned for part 2 where we setup Sysmon and Fleet integrations, and thanks as always for reading!
