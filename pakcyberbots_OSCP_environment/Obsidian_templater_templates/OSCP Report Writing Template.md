<%*
tR += `---
title: "Offensive Security Certified Professional Exam Report"
author: ["your@mail.com", "OSID: OS-00000"]
date: "${tp.date.now("YYYY-MM-DD")}"
subject: "Markdown"
keywords: [Markdown, Example]
subtitle: "OSCP Exam Report"
lang: "en"
titlepage: true
titlepage-color: "1E90FF"
titlepage-text-color: "FFFAFA"
titlepage-rule-color: "FFFAFA"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \\scriptsize

---\n\n`
%>

<%*
const ipText = await tp.system.prompt("Enter IPs (comma-separated) -- T1,T2,T3,MS01,MS02,DC01")
ipList = ipText.split(",").map(ip => ip.trim()).filter(ip => ip.length > 0)
%>
# High-Level Summary

**YourName** was tasked with performing a penetration test against **three standalone** **machines** and **one Active Directory (AD) environment** within a controlled lab. The objective was to identify security weaknesses, simulate real-world exploitation scenarios, and gain full system-level access.

During the engagement, multiple vulnerabilities were discovered and successfully exploited on each target, leading to **initial access**, **lateral movement**, and **privilege escalation**.

During the assessment, YourName identified and exploited multiple critical vulnerabilities across the infrastructure, including:

## Target Summary

### Machine 1: <%* tR += ipList[0] %>
### Machine 2: <%* tR += ipList[1] %>
### Machine 3: <%* tR += ipList[2] %>
### AD Set: <%* tR += ipList[5] %> \[ <%* tR += ipList[3] %>, <%* tR += ipList[4] %> \]

## Recommendations
The following security measures are recommended based on the assessment findings:



# Methodologies

YourName utilized a widely adopted approach to performing penetration testing that is effective in testing how well the OffSec Labs and Exam environments are secure. Below is a breakout of how YourName was able to identify and exploit the variety of systems and includes all individual vulnerabilities found.

## Information Gathering & Enumeration

The information gathering and enumeration phase involved identifying live hosts, mapping exposed services, and gathering metadata to guide exploitation. This step was critical in determining potential attack surfaces across both standalone machines and the Active Directory (AD) environment.


### Scope
**Stand-Alone Machines**

| **No.** | **Machine IP**         | **Name** |
| ------- | ---------------------- | -------- |
| **1**   | <%* tR += ipList[0] %> | Kiero    |
| **2**   | <%* tR += ipList[1] %> | Berlin   |
| **3**   | <%* tR += ipList[2] %> | Gust     |

**Active Directory Set**

| **No.** | **Machine IP**         | **HostName** |
| ------- | ---------------------- | ------------ |
| **1**   | <%* tR += ipList[3] %> | MS01         |
| **2**   | <%* tR += ipList[4] %> | MS02         |
| **3**   | <%* tR += ipList[5] %> | DC01         |
Initial network scans were conducted using Nmap to identify enumerate open services in order to get to find the attack surface.
YourName listed only the services that helped him during the penetration test—specifically for sensitive data discovery, initial access, or privilege escalation.

## Initial Foothold
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, YourName was able to successfully gain access to 6 out of the 6 systems.

## Privilege Escalation
This phase aims to elevate access from a regular user to root (Linux) or administrator/system (Windows).
YourName added administrator and root level accounts on all systems compromised. In addition to the administrative/root access. It includes identifying and abusing.

## House Cleaning
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important.
After capturing the required flags (local.txt and proof.txt) and documenting all findings, YourName removed
temporary files, or malicious artifacts (e.g., .so files) to restore the system to its original state, ensuring minimal footprint post-engagement
YourName removed all user accounts and passwords as well as the Meterpreter services installed on the system. OffSec should not have to remove any user accounts or services from the system.

# Vulnerabilities / Findings

## Target #1 - <%* tR += ipList[0] %>

### \<Vulnerability Name\>
**Explanation:** 

**Impact:**

**Mitigation:**

**Severity:** \textcolor{yellow}{Medium}

## Target #2 - <%* tR += ipList[1] %>

### \<Vulnerability Name\>
**Explanation:** 

**Impact:**

**Mitigation:**

**Severity:** \textcolor{orange}{High}

## Target #3 - <%* tR += ipList[2] %>

### \<Vulnerability Name\>
**Explanation:** 

**Impact:**

**Mitigation:**

**Severity:** \textcolor{red}{Critical}

## Active Directory Set - <%* tR += ipList[5] %>

### \<Vulnerability Name\>
**Explanation:** 

**Impact:**

**Mitigation:**

**Severity:** \textcolor{red}{Critical}

# Lab preparation or Testing setup

Before reviewing the attack narratives for the three standalone machines and the Active Directory environment, please complete the following preparation steps:

- **Assign IP Addresses to Variables**:  
  To simplify command execution throughout the report, assign IP addresses to environment variables using the format below:

```bash
# StandAlone Machines IP Assignment 
export T1_IP=x.x.x.x 
export T2_IP=x.x.x.x
export T3_IP=x.x.x.x 

# AD Machines IP Assignment
export DC_IP=x.x.x.x
export MS01_IP=x.x.x.x 
export MS02_IP=x.x.x.x
```

  > It is recommended to add these lines to your “**.bashrc**” or “**.zshrc**” file to ensure the variables are automatically set in every new terminal session.

- **Review Required Tools and Binaries**:  
  Refer to [***Appendix A & B – Tools Used and Required Binaries***](#a.-tools-used) to install the necessary tools and download all binaries that need to be delivered to the victim machines. Once downloaded, move all binaries into a single directory and assign that path to a variable for easy reference.

```bash
$BIN_DIR=$(pwd)/binaries
mkdir $BIN_DIR 

# You can host these binaries using:
python3 -m http.server 80 -d $BIN_DIR

# Or use the custom tool “fuzzy-httpserver”, which automatically corrects common URL typos on the server side:
pipx install fuzzy-httpserver
fuzzy-httpserver -p 80 -d $BIN_DIR
```

> **Note:** You may notice that binaries are being downloaded from specific web paths on the victim machine. This is a result of my personal setup and organization, as I maintain a large collection of binaries categorized by functionality. For your purposes, it is sufficient to place all required binaries in a single directory and host them using any HTTP server method you prefer.

While the full penetration testing process is documented, readers may skip detailed enumeration steps and directly follow the exploitation and reproduction steps provided for each identified vulnerability.

# StandAlone Machines

## Target #1 – <%* tR += ipList[0] %> - OS

### Port Scanning & Enumeration

The assessment began with an **Nmap** scan to identify open ports and services running on the target system. Alternatively, **Rustscan** ([_See Appendix A_](#a.-tools-used)) can be used to quickly find open ports and then it automatically checks for more details only on open ports using Nmap. The same set of commands was consistently used across all the Standalone Machines as well as the Active Directory Machine to ensure comprehensive port enumeration.

```bash
rustscan -a $IP1 --range 1-65535 -- -A -Pn  | tee portscan

# OR

nmap -A -p- -T4 $IP1
```

| **IP Address**         | **Ports Open** – Service Name with Version                      |
| ---------------------- | --------------------------------------------------------------- |
| <%* tR += ipList[0] %> | **TCP**:  <br>**21** – <br>**22** – <br>**80** – <br>**3389** – |


### Initial Foothold via vuln

### Privilege Escalation via vuln 

## Target #2 – <%* tR += ipList[1] %> - OS

### Port Scanning & Enumeration

| **IP Address**         | **Ports Open** – Service Name with Version                      |
| ---------------------- | --------------------------------------------------------------- |
| <%* tR += ipList[1] %> | **TCP**:  <br>**21** – <br>**22** – <br>**80** – <br>**3389** – |

### Initial Foothold via vuln

### Privilege Escalation via vuln

## Target #3 – <%* tR += ipList[2] %> - OS
### Port Scanning & Enumeration

| **IP Address**         | **Ports Open** – Service Name with Version                      |
| ---------------------- | --------------------------------------------------------------- |
| <%* tR += ipList[0] %> | **TCP**:  <br>**21** – <br>**22** – <br>**80** – <br>**3389** – |

### Initial Foothold via vuln

### Privilege Escalation via vuln

# Active Directory Set 
## MS01 – <%* tR += ipList[3] %>

### Port Scanning & Enumeration

| **IP Address**         | **Ports Open** – Service Name with Version                      |
| ---------------------- | --------------------------------------------------------------- |
| <%* tR += ipList[3] %> | **TCP**:  <br>**21** – <br>**22** – <br>**80** – <br>**3389** – |

### Initial Foothold via vuln

### Privilege Escalation via vuln

### Pivoting Setup

## MS02 – <%* tR += ipList[4] %>

### Port Scanning & Enumeration

| **IP Address**         | **Ports Open** – Service Name with Version                      |
| ---------------------- | --------------------------------------------------------------- |
| <%* tR += ipList[4] %> | **TCP**:  <br>**21** – <br>**22** – <br>**80** – <br>**3389** – |

### Initial Foothold via vuln

### Privilege Escalation via vuln

## DC01 – <%* tR += ipList[5] %>

### Port Scanning & Enumeration

| **IP Address**         | **Ports Open** – Service Name with Version                      |
| ---------------------- | --------------------------------------------------------------- |
| <%* tR += ipList[5] %> | **TCP**:  <br>**21** – <br>**22** – <br>**80** – <br>**3389** – |




# Appendices

## A. Tools Used
- **Rustscan**
- **Penelope**
- **Chisel server**
- **Ligolo-ng server**

**Script to Install:**
```bash
wget https://github.com/bee-san/RustScan/releases/download/2.4.1/x86_64-linux-rustscan.tar.gz.zip
unzip x86_64-linux-rustscan.tar.gz.zip 
tar -xzvf x86_64-linux-rustscan.tar.gz
./rustscan

pipx install git+https://github.com/brightio/penelope

sudo apt install chisel

sudo apt install ligolo-ng
```

## B. Required Binaries for Delivery
Binaries that are required to be delivered to the victim machine as part of the exploitation or post-exploitation process.  
> **Note:** This list does not include exploit code; refer to [***Appendix C***](c.-exploit-code) for exploit implementations.
- **Chisel binary for Linux**
- **WinpeasAny.exe**
- **Ligolo Windows Agent Binary**
- **Print Spoofer**
- **Mimikatz**
- **JuicyPotato**

**Script to Download:**
```bash
$BIN_DIR=$(pwd)/binaries
mkdir $BIN_DIR 
cd $BIN_DIR


wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz
gunzip chisel_1.10.1_linux_amd64.gz
chmod +x chisel_1.10.1_linux_amd64
mv chisel_1.10.1_linux_amd64 chisel-linux

wget https://github.com/peass-ng/PEASS-ng/releases/download/20250701-bdcab634/winPEASany.exe

wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_windows_amd64.zip
unzip ligolo-ng_agent_0.8.2_windows_amd64.zip
mv agent.exe ligolo-agent.exe

wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe

wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
mkdir mimikatz_trunk && unzip mimikatz_trunk.zip -d mimikatz_trunk
mv mimikatz_trunk/x64/mimikatz.exe .
rm -rf mimikatz_trunk

wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
```

## C. Exploit Code

### <%* tR += ipList[0] %>
#### CVE Exploit

### <%* tR += ipList[1] %>
#### CVE Exploit

### <%* tR += ipList[2] %>

### AD Set



## D. Captured Flags

| IP Address (Hostname)  | local.txt | proof.txt |
| ---------------------- | --------- | --------- |
| <%* tR += ipList[0] %> |           |           |
| <%* tR += ipList[1] %> |           |           |
| <%* tR += ipList[2] %> |           |           |
| <%* tR += ipList[3] %> |           |           |
| <%* tR += ipList[4] %> |           |           |
| <%* tR += ipList[5] %> |           |           |

## E. References

