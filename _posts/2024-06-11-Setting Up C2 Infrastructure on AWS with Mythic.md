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
  - [Installing Docker and Mythic](#installing-docker-and-mythic)
    - [Docker Installation](#docker-installation)

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

## Installing Docker and Mythic

### Docker Installation

1. Update the system:
   ```bash
   sudo apt update && sudo apt upgrade -y 
   ```
2. Install Docker:
  ```bash
   sudo apt install docker.io -y
   ```
3. docker --version:
  ```bash
   docker --version
   ```   
4.   