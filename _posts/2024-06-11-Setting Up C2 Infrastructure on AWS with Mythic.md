---
layout: post
title: How to create infrastructure c2
date: 06-11-2024 12:00:00 +0000
image: 
    path: /assets/covers/mythic.png
categories: [Documentation]
tags: [c2, infrastructure, aws, Mythic, Nginx, Docker, Payload]
---

# Documentation: Setting Up C2 Infrastructure on AWS with Mythic

## Table of Contents
- [Documentation: Setting Up C2 Infrastructure on AWS with Mythic](#documentation-setting-up-c2-infrastructure-on-aws-with-mythic)
  - [Table of Contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
  - [AWS Setup](#aws-setup)
    - [Creating an EC2 Instance](#creating-an-ec2-instance)
    - [Creating an EC2 Instance redirector](#creating-an-ec2-instance-redirector)
    - [Security Configuration](#security-configuration)
- [First, we need to create an account on amazon.com](#first-we-need-to-create-an-account-on-amazoncom)
  - [Setting Up the C2 and Redirector](#setting-up-the-c2-and-redirector)
  - [Installing Mythic C2](#installing-mythic-c2)
    - [Update the System](#update-the-system)
  - [Installing Nginx on the Redirector](#installing-nginx-on-the-redirector)
  - [Uploading Our Project](#uploading-our-project)
  - [Generating the Payload](#generating-the-payload)
  - [Conclusion](#conclusion)

---

## Prerequisites

1. An **AWS account** with permissions to create EC2 instances and configure VPCs.
2. Basic knowledge of **Docker**, networking, and AWS configuration.
3. **Authorization and control** over systems where Mythic agents will be deployed.

---

## AWS Setup

### Creating an EC2 Instance

1. Log into your AWS console and go to **EC2**.
2. Click on **Launch Instance**.
3. Select an **Ubuntu 20.04** (or similar) AMI (Amazon Machine Image).
4. Choose an instance type appropriate for your needs; a **t2.medium** should suffice.
5. Configure network details, ensuring:
   - An **Elastic IP** is assigned to the instance for external access.
   - A **VPC** and subnet in a region that allows for secure and fast connections.
### Creating an EC2 Instance redirector

### Security Configuration

1. In the **Security Group** section, set up rules to allow traffic on:
   - **HTTP (80)** for web interface.
   - **HTTPS (443)** if using SSL/TLS.
   - **TCP (7443)** for Mythic connections (default port).
2. Restrict access to trusted IP addresses or enable MFA for SSH connections.

---




# First, we need to create an account on [amazon.com](https://aws.amazon.com/es/ec2/)

![](/assets/post/c2/in.png)

In the search bar, we will look for **EC2** and enter:

![](/assets/post/c2/in2.png)

We will create **2 instances** in the Amazon cloud that will store Linux or Ubuntu distributions. To do this, we click on the orange **Launch instance** button:

![](/assets/post/c2/instances2.png)

---

## Setting Up the C2 and Redirector

First, let’s configure our **C2** and then our **redirector**:

![](/assets/post/c2/instance4.png)

It is important to create our key pair because once created, it cannot be downloaded again. We will finish configuring the **network settings** once we have our redirector as well:

![](/assets/post/c2/o.png)

Configure the storage it will have:

![](/assets/post/c2/instance5.png)

Finally, we launch the instance, and it will look like this:

![](/assets/post/c2/instance6.png)

Now we will create our **redirector** with the same procedure—launch an instance along with new keys:

![](/assets/post/c2/instance7.png)

We will temporarily edit the **inbound rules** of our redirector as follows:

![](/assets/post/c2/red.png)

Next, we modify our instance where we will have our **C2**:

![](/assets/post/c2/red2.png)

---

## Installing Mythic C2

- **`chmod 600`**: Restricts access to the file owner, meeting SSH requirements.  
  We grant **600** permissions to our keys so we can use them:

![](/assets/post/c2/c2.png)

Run the command as follows to access our Ubuntu environment, where we will install our C2:

![](/assets/post/c2/mythics.png)

### Update the System

![](/assets/post/c2/c2keys.png)

We will use the Mythic documentation for its installation:  
[Mythic Installation Docs](https://docs.mythic-c2.net/installation)  
Repository: [https://github.com/its-a-feature/Mythic](https://github.com/its-a-feature/Mythic)

Clone the repository:

```bash
git clone https://github.com/its-a-feature/Mythic --depth 1
```
![](/assets/post/c2/mythic2.png)

Install Docker:
```bash
sudo apt install -y docker.io
```
![](/assets/post/c2/mythic3.png)

Install Docker Compose:
```bash
sudo apt install -y docker-compose
```
![](/assets/post/c2/mythic4.png)

Run the installation script for Ubuntu:
```bash
sudo ./install_docker_ubuntu.sh
```
![](/assets/post/c2/mythic5.png)

We install make, run the make file, and enable Docker:
```bash
sudo make
sudo systemctl status docker
```
![](/assets/post/c2/mythic6.png)

Start Mythic:
```bash
sudo ./mythic-cli start
```
![](/assets/post/c2/mythic7.png)

Install the C2 Agents:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/apfell
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
sudo ./mythic-cli install github https://github.com/MythicAgents/apollo
```
Add an inbound rule to our C2 (main) instance for port forwarding:

![](/assets/post/c2/port.png)

We forward port 7443. In a new terminal, run the following command:

![](/assets/post/c2/mythic8.png)

Check the Mythic web interface with the following URL:
```pgsql
https://127.0.0.1:7443/new/login
```
![](/assets/post/c2/mythic9.png)

We look for the password generated by Mythic in its folder as follows:
```bash
cat .env | grep -iF "PASS"
```
Log in to Mythic and verify that our agents are online:

![](/assets/post/c2/agents.png)

## Installing Nginx on the Redirector

Access the instance using its corresponding public IP:

![](/assets/post/c2/nginx.png)

Update Ubuntu:
```bash
sudo apt update && upgrade
```
![](/assets/post/c2/nginx2.png)

Install nginx:
```bash
sudo apt install nginx -y
```
Check if the service is running:
```bash
sudo systemctl status nginx
```
![](/assets/post/c2/nginx3.png)

Check the web:

![](/assets/post/c2/nginx4.png)

Now you can get a domain of your choice with an SSL certificate and modify the DNS:

![](/assets/post/c2/dns.png)

Go to Route 53 to configure your domain:

![](/assets/post/c2/dns2.png)

Just confirm that in the Value field, you put the public IP address of the redirector:

![](/assets/post/c2/dns3.png)

---

## Uploading Our Project

We upload our project that simulates a doctors or medical website:

![](/assets/post/c2/dns4.png)

Now we need to create our payload generated with Mythic:

![](/assets/post/c2/dns5.png)

Check the final configuration:

![](/assets/post/c2/web.png)

## Generating the Payload

Upload our simulated medical website project.

![](/assets/post/c2/web2.png)

Generate the **payload**.

![](/assets/post/c2/payload.png)

![](/assets/post/c2/payload2.png)


Select operate system 
![](/assets/post/c2/payload3.png)
![](/assets/post/c2/agent.png)

Select our commands that we want our payload to have:

![](/assets/post/c2/payload4.png)

We set up our c2 profile

![](/assets/post/c2/payload5.png)



Our **callbackhost** is modified to our domain and the value is our user **agent**, the random address

![](/assets/post/c2/payload6.png)


We name our agent the way we set it up in our nginx

![](/assets/post/c2/payload7.png)
![](/assets/post/c2/payload8.png)


We have our **payload** generated now we need to move it to our instance as follows:

![](/assets/post/c2/payload9.png)


Verify the final configuration.

![](/assets/post/c2/fin.png)




## Conclusion

In this guide, we have successfully set up and configured a **Mythic C2** infrastructure using AWS EC2 instances. We have covered the following key steps:

1. **Deploying EC2 instances** for both the C2 server and the redirector.
2. **Configuring SSH key pairs** to securely access the instances.
3. **Installing and configuring Mythic C2**, including Docker and necessary dependencies.
4. **Setting up Nginx as a redirector** to enhance security and obfuscation.
5. **Generating and deploying payloads** through Mythic C2 for post-exploitation activities.

By following these steps, you now have a working Mythic C2 setup that allows you to manage agents and conduct **authorized** red team engagements.
