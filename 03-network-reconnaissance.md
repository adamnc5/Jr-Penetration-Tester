# 03 — Network Reconnaissance

> **TryHackMe · Jr Penetration Tester**  
> **Status:** Completed · **Rooms:** 4/4  
> **Type:** Personal technical notes — concepts, commands, examples, and security implications (not a flag walkthrough)

[← Back to the pathway overview](../README.md)

## Overview

**Network reconnaissance** is the process of collecting information about a target's systems, network infrastructure, and services before deeper security testing. The goal is to understand **what exists, how it communicates, what is exposed, and where a security assessment should focus**.

This module starts with **passive reconnaissance**, moves into **active interaction with systems**, explains everyday **network protocols**, and finally covers how **cleartext traffic and weak authentication** can be attacked—and how **TLS and SSH** help protect communications.

### Rooms covered

| Room | Main focus |
|---|---|
| [Passive Reconnaissance](https://tryhackme.com/room/passiverecon) | WHOIS/RDAP, DNS records, subdomains, Certificate Transparency, Shodan |
| [Active Reconnaissance](https://tryhackme.com/room/activerecon) | Web browsers, `ping`, `traceroute`, `telnet`, `netcat` |
| [Protocols and Servers](https://tryhackme.com/room/protocolsandservers) | Telnet, HTTP, FTP, SMTP, POP3, IMAP |
| [Protocols and Servers 2](https://tryhackme.com/room/protocolsandservers2) | Sniffing, MITM, TLS, SSH, password attacks |

**Scope rule:** All direct probing, scanning, authentication testing, and packet capture in these notes refer to **systems and traffic I own or have explicit permission to test**. Replace `LAB_IP` and `LAB_HOST` with an authorized TryHackMe target. Commands that use `example.com` are illustrative and should not be treated as permission to test that domain.

### Contents

1. [Passive Reconnaissance](#1-passive-reconnaissance)
2. [Active Reconnaissance](#2-active-reconnaissance)
3. [Protocols and Servers](#3-protocols-and-servers)
4. [Protocols and Servers 2](#4-protocols-and-servers-2)
5. [Common Ports](#5-quick-reference--common-ports)
6. [Command Cheat Sheet](#6-command-cheat-sheet)
7. [Common Mistakes](#7-common-mistakes-to-avoid)
8. [Practical Workflow](#8-practical-pentesters-workflow)
9. [Final Takeaways](#9-final-takeaways)
10. [Glossary](#10-glossary)

---

## 1. Passive Reconnaissance

**Passive reconnaissance** collects intelligence from publicly accessible information sources **without directly contacting the target's hosts or employees**.

Examples: searching domain-registration databases, asking a public DNS resolver about a domain, reviewing publicly logged TLS certificates, and looking at Shodan's already-indexed data.

### 1.1 Passive versus active reconnaissance

| Passive reconnaissance | Active reconnaissance |
|---|---|
| Uses publicly available or third-party information | Sends traffic to the target or directly engages with it |
| Typically does not appear in the target's service logs | Can appear in access logs, firewall logs, and IDS alerts |
| WHOIS/RDAP, public DNS resolvers, CT logs, Shodan | `ping`, `traceroute`, service connections, web requests |
| Reveals a likely attack surface | Verifies how accessible systems and services actually behave |

**Important nuance:** DNS lookups through a third-party recursive resolver are generally treated as passive in the room. Querying an organization's **authoritative DNS servers directly** or performing a zone transfer is direct interaction and may count as active testing. Passive does not mean information is guaranteed correct or current.

### 1.2 WHOIS and RDAP: domain registration information

**WHOIS** is a traditional service for retrieving domain-registration information. It may reveal:

- The **registrar** (the company through which a domain was registered).
- **Creation, modification, and expiration dates**.
- **Name servers**, which indicate where the domain's authoritative DNS is hosted.
- Registration status codes and, where available, contact information.

```bash
# Legacy WHOIS lookup
whois example.com
```

**RDAP** (Registration Data Access Protocol) is the modern, HTTPS- and JSON-based replacement for traditional WHOIS for generic top-level domains. Personal registrant details are often redacted for privacy.

```bash
# Example: query an RDAP endpoint for a .com domain
curl -s https://rdap.verisign.com/com/v1/domain/example.com | jq .
```

**Interpretation:** Name servers may identify a DNS provider; the registrar is **not** necessarily the provider hosting the website or mail. Registration dates and other values can change and should be verified before reporting.

### 1.3 DNS: turning names into records

The **Domain Name System (DNS)** helps clients locate services and retrieve other records associated with a domain.

| Record | What it tells us | Example meaning |
|---|---|---|
| `A` | IPv4 address for a hostname | Where `www.example.com` resolves over IPv4 |
| `AAAA` | IPv6 address for a hostname | Where it resolves over IPv6 |
| `CNAME` | Alias from one hostname to another | `www` points to a hosting provider's name |
| `MX` | Mail-exchange hosts for a domain | Which servers receive mail for `@example.com` |
| `NS` | Authoritative DNS name servers | Which name servers serve a zone |
| `SOA` | Zone authority and administrative metadata | Zone serial and timing fields |
| `TXT` | Text records used for several purposes | SPF, DKIM, DMARC, ownership verification |

**A and AAAA records:** These give addresses associated with a queried **hostname**, not necessarily the organization's origin server. With a CDN, an address can belong to an intermediary such as a reverse proxy.

**MX records:** A company can use a third-party mail provider. The MX records indicate which servers are responsible for accepting mail for the domain—not the company's employee email addresses.

**TXT records:** Store text; often include email authentication policies:

- **SPF:** Specifies which sending servers are authorized by a domain's published policy.
- **DKIM:** Publishes public keys used to verify cryptographic signatures on email.
- **DMARC:** States how recipients should handle messages that fail domain-alignment checks and where to send reports.

#### `nslookup` and `dig`

```bash
# Basic hostname lookup
nslookup example.com

# Query a specific record type
nslookup -type=MX example.com
nslookup -type=TXT example.com 1.1.1.1

# dig: specify the record type
dig example.com A
dig example.com AAAA
dig example.com MX
dig example.com TXT

# Ask a specific public recursive resolver
dig @1.1.1.1 example.com MX

# Show a concise answer section
dig example.com NS +noall +answer
```

**How to read `dig`:**

```text
example.com.    300    IN    MX    10    mail.example.com.
     NAME      TTL  CLASS  TYPE PRIORITY      MAIL HOST
```

- **TTL** is the number of seconds a DNS answer may be cached; it is not the network packet's hop-limit TTL.
- **`IN`** means the Internet DNS class.
- For **MX priority**, a **lower number is preferred**.
- DNS answers can change due to caching, configuration updates, load balancing, or CDNs.

**Real-world use:** DNS records can help build a list of likely web, email, and infrastructure assets to validate during an authorized assessment. A DNS result alone does **not** prove that the resolved IP is in the permitted test scope.

### 1.4 Subdomain discovery: DNSDumpster and Certificate Transparency

A **subdomain** is a name beneath another domain, such as `portal.example.com` or `mail.example.com`.

Why it matters: Subdomains sometimes point to separate applications, forgotten development environments, administrative interfaces, or third-party services. Each may have different security controls.

**DNSDumpster** aggregates public DNS and other OSINT data to show hostnames, related IP addresses, and infrastructure relationships.

- Site: https://dnsdumpster.com/
- Useful output: hostnames, DNS relationships, and network visualizations.

**Certificate Transparency (CT)** logs publicly record information about issued TLS certificates. Their **Subject Alternative Name (SAN)** entries can reveal additional hostnames.

- Site: https://crt.sh/
- Example search: `%.example.com`

**Limits:** A CT entry means a certificate was issued, **not** that a subdomain is currently live. Results can also contain old, duplicate, wildcard, or third-party names. Check scope before later interacting with any discovered host.

### 1.5 Shodan: internet-exposed service intelligence

**Shodan** indexes information collected from internet-facing devices and services. Instead of searching page content like a normal search engine, it can return **IP addresses, open ports, service banners, software indicators, certificates, and hosting information**.

- Site: https://www.shodan.io/

Illustrative search filters:

```text
hostname:example.com
port:443 country:US
org:"Example Organization"
```

**What to look for:**

1. Which services are publicly accessible?
2. Are there exposed management interfaces or unexpected ports?
3. Which software names or versions are advertised?
4. Do the results identify a CDN, shared hosting, or an actual organization-controlled host?

**Important:** Shodan results reflect **previous observations** and may be outdated. A listed software version is not proof that the system is vulnerable. You must also confirm ownership and scope before making direct requests.

### Passive reconnaissance takeaway

Start by learning what the internet **already knows about the target**. Gather leads, label uncertainty, avoid treating inferred ownership as fact, and save candidate assets for authorized validation.

---

## 2. Active Reconnaissance

**Active reconnaissance** involves direct interaction with a target. It can reveal information not available from public databases, but the target may record or block the activity.

### 2.1 Web browsers and Developer Tools

A normal web browser is already a reconnaissance tool. Visiting a website contacts its infrastructure, so browsing an in-scope target is **active** rather than passive.

Browser **Developer Tools** (often `F12` or `Ctrl+Shift+I`) expose important details:

| Tab | What to inspect |
|---|---|
| **Network** | HTTP requests, response codes, headers, cookies, API calls, redirects |
| **Sources** | JavaScript, HTML, CSS, referenced endpoints, comments |
| **Application / Storage** | Cookies, local storage, session storage |
| **Security** | TLS certificate, issuing authority, valid dates, hostname coverage |
| **Console** | JavaScript errors and troubleshooting information |

**Potential discoveries:** An endpoint referenced in JavaScript, a response header exposing a server framework, or a certificate listing additional subdomains.

These are **leads**, not vulnerabilities by themselves. For example, an API endpoint is not insecure just because it is visible.

### 2.2 `ping`: ICMP host reachability

`ping` usually sends **ICMP Echo Request** packets and waits for **Echo Replies**.

```bash
# Linux: send four echo requests
ping -c 4 LAB_IP

# Windows: send four echo requests
ping -n 4 LAB_IP

# Linux: use IPv6 when appropriate
ping -6 -c 4 LAB_HOST
```

A successful response may look like:

```text
64 bytes from LAB_IP: icmp_seq=1 ttl=62 time=3.2 ms
```

| Field | Meaning |
|---|---|
| `icmp_seq` | Sequence number of the request/reply |
| `ttl` | Remaining IP hop limit in the reply packet |
| `time` | Round-trip time for the request and response |
| Packet loss | Percentage of transmitted probes that received no valid reply |

**Don't confuse the two TTLs:** An IP packet's **TTL** decreases as it travels through routers. A DNS record's **TTL** controls caching time.

**Most important limitation:** **No ping reply does not prove a host is offline.** ICMP may be blocked or rate-limited. Likewise, initial TTL values sometimes hint at an operating system, but OS identification from TTL alone is unreliable.

### 2.3 `traceroute`: map the path through routers

`traceroute` sends probes with increasing IP TTL values. Each router that reduces the TTL to zero may respond with an **ICMP Time Exceeded** message, revealing a hop in the path.

```bash
# Linux
traceroute LAB_IP

# Windows equivalent
tracert LAB_IP

# Variants used for different network conditions
traceroute -I LAB_IP  # ICMP probes
traceroute -T LAB_IP  # TCP probes
mtr LAB_IP            # Traceroute-like view plus ongoing statistics
```

**Reading results:**

```text
1  192.0.2.1       1.2 ms
2  *               *
3  198.51.100.1   12.4 ms
```

The addresses above are **illustrative documentation addresses**, not live lab results.

- Each numbered line is a possible **hop** toward the destination.
- A `*` usually means a probe timed out; it does **not** necessarily mean that router or every later hop is down.
- Routes can change because of load balancing and dynamic routing.
- Some routers do not reveal themselves, and paths can be asymmetric.

### 2.4 Telnet: remote terminal protocol and banner grabbing

**Telnet**, commonly TCP **port 23**, was designed for remote command-line access. It is unsafe for sensitive administration because its traffic, including credentials, is normally **unencrypted**.

For reconnaissance, the **telnet client** can also make a raw TCP connection to other ports and let us inspect unencrypted protocol responses.

```bash
# Open an HTTP connection to an authorized lab host
telnet LAB_IP 80
```

After connecting, type an HTTP request, then send a **blank line**:

```http
GET / HTTP/1.1
Host: lab.local

```

A response might include:

```text
HTTP/1.1 200 OK
Server: nginx
Content-Type: text/html
```

**Banner grabbing** means reading the information a service exposes when a connection is made or a request is sent. A banner may suggest the service software or version, although banners can be removed, modified, or misleading.

**Critical distinction:** Using `telnet` as a basic TCP client against an HTTP lab port does **not** mean the HTTP server itself is a Telnet server.

### 2.5 Netcat (`nc`): the TCP/UDP multipurpose tool

**Netcat** can initiate connections to services or listen for incoming connections. It is useful for checking connectivity, retrieving banners, and testing basic client/server interactions.

```bash
# Connect to an authorized lab service
nc -nv LAB_IP 80

# Try to establish a TCP connection without sending application data
nc -vz LAB_IP 80

# In one authorized lab terminal, listen on port 4444
nc -lvnp 4444

# From a second lab machine, connect to that listener
nc LAB_LISTENER_IP 4444
```

The exact `nc` flags vary between versions (OpenBSD netcat, traditional netcat, and Ncat). A successful TCP connection means a connection was accepted, **not** that the service is secure or that every feature works.

### Active reconnaissance takeaway

Use the **least intrusive, in-scope checks** that answer the question. Record which hosts respond, what protocol is on each port, which clues are uncertain, and how a defender might detect the probes.

---

## 3. Protocols and Servers

A **protocol** is an agreed set of rules for how two systems communicate. A **server** listens for requests or messages; a **client** initiates the relevant interaction.

Understanding the actual commands and responses helps explain why specific security risks exist.

### 3.1 Telnet — plaintext remote access

- **Typical port:** TCP **23**.
- **Purpose:** Remote text-based terminal access.
- **Problem:** Credentials and commands are not protected from interception by the protocol.
- **Preferred replacement:** **SSH**, which provides encrypted remote access and authenticates the server.

### 3.2 HTTP — web communication

**HTTP** is a request/response protocol used by browsers, APIs, and web servers.

1. The **client** sends a request with a method, path, headers, and sometimes a body.
2. The **server** sends a response with a status code, headers, and optionally a body.

```http
GET /index.html HTTP/1.1
Host: lab.local

```

```http
HTTP/1.1 200 OK
Content-Type: text/html

```

| Element | What it means |
|---|---|
| `GET` | Retrieve a resource |
| `POST` | Submit data to be processed |
| `200 OK` | Request succeeded |
| `301/302` | Redirect |
| `401` | Authentication required or invalid |
| `403` | Request forbidden |
| `404` | Resource not found |
| `500` | Internal server error |

- **HTTP:** Commonly TCP **80**, unencrypted.
- **HTTPS:** Commonly TCP **443** with **TLS**. Modern HTTP/3 uses QUIC over UDP 443.

```bash
# Inspect headers from an authorized web service
curl -I http://LAB_IP

# Request a page while showing response headers
curl -i http://LAB_IP/
```

**Security concern:** Sensitive data sent over plain HTTP may be visible or modifiable by an on-path attacker. HTTPS protects the connection in transit, but it does **not** automatically fix weak application authorization or injection vulnerabilities.

### 3.3 FTP — file transfers and two connections

**FTP** (File Transfer Protocol) moves files between a client and a server. Traditional FTP commonly uses **two separate TCP connections**:

1. **Control connection:** Commands, login, and replies, usually to server port **21**.
2. **Data connection:** Actual file listings or file contents, using ports determined by the selected mode.

Typical FTP commands include:

| Command | Purpose |
|---|---|
| `USER` | Send username |
| `PASS` | Send password |
| `PWD` | Display working directory |
| `LIST` | Request directory listing |
| `RETR` | Retrieve a file |
| `STOR` | Upload a file |
| `QUIT` | End session |

#### Active FTP versus passive FTP

| | Active mode | Passive mode |
|---|---|---|
| **Who starts the data connection?** | Server connects **to client** | Client connects **to server** |
| **Common ports** | Server typically uses port **20** for data | Server advertises a dynamic listening port |
| **Firewall/NAT consideration** | Inbound connection to the client can be blocked | Usually easier for clients behind NAT or firewalls |

**Example:** A user downloads one file. The **control connection** carries a command such as `RETR report.txt`; the **data connection** carries the file itself.

**Key security concern:** Standard FTP sends usernames, passwords, and file data without transport encryption. Safer alternatives are:

- **FTPS:** FTP protected by TLS; retains FTP-style control and data connections.
- **SFTP:** SSH File Transfer Protocol; **not** FTP with TLS, and normally uses an SSH connection on TCP **22**.

### 3.4 SMTP — sending email

**SMTP** (Simple Mail Transfer Protocol) is used to **submit or relay outgoing email** between clients and servers or between mail servers.

```text
Sender's mail client
      |
      v
Outgoing SMTP server
      |
      v
Recipient domain's mail server (chosen using MX records)
      |
      v
Recipient's mailbox
```

Common SMTP commands:

| Command | Purpose |
|---|---|
| `EHLO` | Introduce client and request supported SMTP features |
| `MAIL FROM:` | Specify envelope sender |
| `RCPT TO:` | Specify envelope recipient |
| `DATA` | Start transmitting email headers and body |
| `QUIT` | Close the SMTP session |

SMTP replies use numeric status codes; for example, **`220`** commonly indicates a ready server, and **`250`** indicates a successful action.

**Common ports:**

- **25:** SMTP server-to-server relay, often with STARTTLS where supported.
- **587:** Message submission, commonly using STARTTLS.
- **465:** Message submission using implicit TLS.

**Why this matters:** SMTP's envelope information, visible sender fields, and acceptance rules are different things. Email authentication technologies such as **SPF, DKIM, and DMARC** help receiving systems assess whether messages claiming to be from a domain are legitimate. Encryption alone does not stop email spoofing.

### 3.5 POP3 — downloading mail

**POP3** (Post Office Protocol version 3) is a protocol used by mail clients to **retrieve messages** from a mailbox server.

- **TCP 110:** Plain POP3, optionally upgraded to TLS using **STLS** when supported.
- **TCP 995:** POP3 using TLS from the start (**POP3S**).

Common commands:

| Command | Purpose |
|---|---|
| `USER` / `PASS` | Authenticate (in simple username/password mode) |
| `STAT` | Get message count and total size |
| `LIST` | List messages and sizes |
| `RETR` | Retrieve a message |
| `DELE` | Mark a message for deletion |
| `QUIT` | End session and apply pending deletions when appropriate |

**Important:** POP3 can be configured to **leave messages on the server**; it does not always delete email immediately after download.

### 3.6 IMAP — synchronizing server-side mail

**IMAP** (Internet Message Access Protocol) keeps messages organized on the **mail server** and supports multiple devices accessing the same mailbox.

- **TCP 143:** Plain IMAP or IMAP upgraded using **STARTTLS**.
- **TCP 993:** IMAP over implicit TLS (**IMAPS**).

IMAP supports working with folders, retrieving selected messages, and updating flags like read/unread or deleted. Because operations apply to the server mailbox, changes can appear across a phone, laptop, and webmail client.

#### POP3 versus IMAP versus SMTP

| Protocol | Main responsibility | Typical real-world example |
|---|---|---|
| **SMTP** | **Send/relay** mail | Send a message to a classmate |
| **POP3** | **Retrieve/download** mail | Download messages for local reading |
| **IMAP** | **Access/synchronize** server mailbox | Read on a laptop and see it marked read on a phone |

**Simple mental model:** **SMTP sends; POP3 downloads; IMAP synchronizes.** All three may be involved in an email service, but sending and retrieving are separate jobs.

### Protocols and Servers takeaway

A service's **port** suggests its protocol, but **does not prove it**. Understanding each protocol's purpose and basic conversation helps recognize **plaintext credentials, exposed banners, incorrect access controls, and legacy services**.

---

## 4. Protocols and Servers 2

The final room focuses on the **security of communications**: how information can be intercepted or altered, how weak passwords can be guessed, and how modern encrypted protocols reduce those risks.

### 4.1 CIA and DAD: security goals and threats

| Security goal (CIA) | Meaning | Related attack outcome (DAD) |
|---|---|---|
| **Confidentiality** | Only authorized people can read information | **Disclosure** of information |
| **Integrity** | Information is accurate and not improperly changed | **Alteration** of information |
| **Availability** | Authorized users can access systems when needed | **Destruction/disruption** of access or data |

A successful packet-capture attack may expose a password (**confidentiality**). A man-in-the-middle attack may change a message (**integrity**). Flooding a service can impair **availability**.

### 4.2 Sniffing: inspecting packets

**Packet sniffing** means capturing or inspecting network traffic. It can be legitimate troubleshooting or security monitoring—or part of an attack.

Tools such as **Wireshark**, **tcpdump**, and **TShark** help inspect packet structure and protocol data.

```bash
# Read a previously captured packet file from an authorized lab
tcpdump -nn -r lab-capture.pcap

# Capture HTTP traffic on an authorized test interface
sudo tcpdump -i eth0 -nn 'tcp port 80'

# Display ASCII payload when suitable for a plaintext lab
sudo tcpdump -i eth0 -nn -A 'tcp port 80'
```

**Flags:**

| Option | Meaning |
|---|---|
| `-i eth0` | Capture on interface `eth0` |
| `-nn` | Do not resolve hostnames or port names |
| `-r FILE` | Read an existing capture file |
| `-A` | Print packet payload in ASCII when possible |
| `tcp port 80` | Capture/filter TCP traffic using port 80 |

**What is exposed?** Unencrypted application data can be readable in captured packets. TLS normally hides application payloads from a passive observer, but other metadata—such as IP addresses, ports, and some connection information—can remain visible.

**Nuance:** Being connected to the same Wi-Fi or switched network does **not** automatically grant visibility into everyone's traffic. What a device can capture depends on network design, permissions, isolation, and position in the traffic path.

### 4.3 Man-in-the-Middle (MITM): intercepting a conversation

A **MITM** attack occurs when an attacker positions themselves between two communicating parties and can observe, relay, or attempt to **modify** their exchange.

```text
Without interception:
Client -------------------------- Server

With an on-path attacker:
Client -------- Attacker -------- Server
```

Examples of possible attack mechanisms include rogue access points, compromised network equipment, and address-resolution manipulation on poorly protected local networks.

**Risks:** Credential theft, altered downloads, modified responses, and session compromise—particularly when traffic is unencrypted or authenticity checks are ignored.

**Defenses:** TLS certificate validation, HTTPS, secure Wi-Fi, trustworthy SSH host-key verification, network protections, and avoiding unexpected certificate warnings. Encryption is not useful if the client accepts an impostor's identity without checking.

### 4.4 TLS: encryption, authenticity, and integrity in transit

**TLS (Transport Layer Security)** is used by HTTPS and many other secure application protocols. It establishes keys and protects application traffic from being read or altered by parties that do not hold those keys.

**Simplified TLS flow:**

1. **Client connects** and proposes compatible security parameters.
2. **Server proves its identity** with a certificate (for typical HTTPS).
3. **Client verifies** the certificate, hostname, validity, and trusted chain.
4. Both sides establish **session keys** using the negotiated handshake.
5. They exchange **encrypted and integrity-protected** application data.

**TLS is not the same as SSL.** SSL is an older, obsolete family of protocols; the modern protocol is TLS.

#### Implicit TLS versus STARTTLS

- **Implicit TLS:** TLS starts **immediately** when the connection begins. Examples: HTTPS **443**, POP3S **995**, IMAPS **993**, SMTP submission **465**.
- **STARTTLS/STLS:** The connection starts using a protocol capable of requesting a switch to TLS; after a successful upgrade, subsequent traffic is encrypted. Examples: SMTP submission **587**, IMAP **143**, POP3 **110** (with STLS).

**Security note:** The availability of STARTTLS does not prove every session used it. The service and client must **require** suitable encryption and correctly validate certificates when security depends on it. Opportunistic encryption can be downgraded if badly configured.

```bash
# Inspect a lab HTTPS certificate and TLS connection
openssl s_client -connect LAB_HOST:443 -servername LAB_HOST

# Inspect a lab SMTP service that supports STARTTLS
openssl s_client -starttls smtp -connect LAB_HOST:587 -servername LAB_HOST
```

**Useful distinction:** **HTTPS = HTTP over TLS**. TLS protects data **in transit**; it does not protect against an already-compromised endpoint or automatically fix broken application security.

### 4.5 SSH: secure remote administration

**SSH (Secure Shell)** typically uses TCP **22** and provides an encrypted, authenticated channel for remote terminal access and other services.

```bash
# Connect to an authorized SSH lab server
ssh labuser@LAB_IP

# Use a different SSH port, if configured
ssh -p 2222 labuser@LAB_IP

# Authenticate with an authorized private key
ssh -i ~/.ssh/lab_key labuser@LAB_IP
```

**Important SSH protections:**

- Encrypts terminal commands and their output.
- Protects data integrity in transit.
- Uses **server host keys** to help clients detect impersonation.
- Supports password authentication and **public-key authentication**.

**SSH is not TLS.** It is its **own secure protocol**. Likewise, **SFTP** uses SSH, while **FTPS** secures FTP with TLS.

**Do not blindly accept a changed host key.** A mismatch can mean a legitimate server rebuild—or an interception attempt. Verify it through a trusted channel.

### 4.6 Password attacks and Hydra

Authentication weaknesses can expose a service even when its network transport is encrypted.

| Attack | Basic idea |
|---|---|
| **Brute force** | Try many possible passwords systematically |
| **Dictionary attack** | Try candidates from a wordlist |
| **Password spraying** | Try a small number of common passwords across many accounts |
| **Credential stuffing** | Test username/password pairs leaked from other services |

**Hydra** is a tool for performing automated login attempts against supported services. It helps assess the effectiveness of password policies and authentication defenses in **approved labs or engagements**.

```bash
# Authorized training example: test one designated lab account
# using a controlled, tiny lab wordlist
hydra -l labuser -P ./lab-passwords.txt -t 2 ssh://LAB_IP
```

- **`-l labuser`:** Test one specified username.
- **`-P ...`:** Read candidate passwords from a wordlist.
- **`-t 2`:** Use two parallel connections/tasks for the test.
- **`ssh://LAB_IP`:** Target an authorized SSH service.

**A successful password guess does not mean that SSH encryption is broken.** It means the login credentials or surrounding authentication controls were insufficient.

**Defenses:** Strong unique passwords, MFA where supported, login throttling, alerts for repeated failures, appropriate account lockout/risk controls, preventing password reuse, and disabling unnecessary authentication methods. Avoid running automated guesses against any live system without explicit authorization and agreed limits.

### Protocols and Servers 2 takeaway

**Encryption protects network traffic; authentication protects account access; authorization controls permitted actions.** All three matter. A properly encrypted SSH session can still be compromised with a weak password, and HTTPS does not make an insecure web application safe.

---

## 5. Quick Reference — Common Ports

| Protocol/service | Common TCP/UDP port(s) | Notes |
|---|---|---|
| DNS | UDP/TCP **53** | UDP commonly used for queries; TCP also used for various DNS operations |
| WHOIS | TCP **43** | Legacy domain-registration protocol; RDAP uses HTTPS |
| HTTP | TCP **80** | Plain HTTP |
| HTTPS | TCP **443**, UDP **443** | HTTPS over TCP/TLS; HTTP/3 over QUIC/UDP |
| FTP control | TCP **21** | Commands and authentication |
| FTP active data | Commonly TCP **20** | Typically server-originated; passive mode uses dynamic data ports |
| SSH / SFTP | TCP **22** | Encrypted administration / file transfer over SSH |
| Telnet | TCP **23** | Unencrypted remote terminal |
| SMTP relay | TCP **25** | Server-to-server mail |
| SMTP submission | TCP **587**, **465** | STARTTLS commonly on 587; implicit TLS on 465 |
| POP3 / POP3S | TCP **110**, **995** | Plain/upgradable vs implicit TLS |
| IMAP / IMAPS | TCP **143**, **993** | Plain/upgradable vs implicit TLS |

**Reminder:** These are **common defaults**, not a guarantee of which protocol is running at any given port.

## 6. Command Cheat Sheet

```bash
# ===== Passive reconnaissance =====
whois example.com
curl -s https://rdap.verisign.com/com/v1/domain/example.com | jq .
dig example.com A
dig example.com AAAA
dig example.com MX
dig example.com TXT
dig @1.1.1.1 example.com NS
nslookup -type=MX example.com
# Browsers: DNSDumpster, crt.sh, Shodan

# ===== Active reconnaissance: authorized lab targets only =====
ping -c 4 LAB_IP
traceroute LAB_IP
traceroute -T LAB_IP
mtr LAB_IP
nc -vz LAB_IP 80
telnet LAB_IP 80
curl -I http://LAB_IP
curl -i http://LAB_IP/

# ===== Secure services and traffic =====
ssh labuser@LAB_IP
openssl s_client -connect LAB_HOST:443 -servername LAB_HOST
openssl s_client -starttls smtp -connect LAB_HOST:587 -servername LAB_HOST
tcpdump -nn -r lab-capture.pcap

# ===== Authorized account-password audit in a lab =====
hydra -l labuser -P ./lab-passwords.txt -t 2 ssh://LAB_IP
```

## 7. Common Mistakes to Avoid

1. **"Passive means nobody can ever know."** Public sources are lower-contact, but queries can still be logged by the third-party service, and some techniques cross into active interaction.
2. **"The A record reveals the company's actual server."** It can point to a proxy, CDN, load balancer, or third-party provider.
3. **"No ping response means the host is down."** Firewalls frequently block ICMP.
4. **"A port number tells me exactly what is running."** Services can use non-standard ports, and banners may be misleading.
5. **"FTP uses just one connection for everything."** FTP has separate **control and data** connections.
6. **"Passive FTP means the server initiates the data connection."** The **client initiates** the data connection in passive FTP.
7. **"POP3 always deletes downloaded email."** Whether messages remain on the server depends on client and server settings.
8. **"SFTP and FTPS are interchangeable."** SFTP uses SSH; FTPS uses TLS with FTP.
9. **"TLS prevents every network or web attack."** TLS protects connections in transit, not compromised endpoints, broken access controls, or weak passwords.
10. **"A successful password attack means encryption failed."** Account authentication can fail even when transport encryption works perfectly.

## 8. Practical Pentester's Workflow

A high-level sequence for a **permitted** assessment:

```text
Define scope and obtain permission
             |
             v
Passive reconnaissance
(WHOIS/RDAP, DNS, CT logs, Shodan)
             |
             v
Build candidate asset list
(verify ownership and scope)
             |
             v
Active reconnaissance
(browser, ping, traceroute, service connections)
             |
             v
Understand exposed protocols
(HTTP, FTP, SMTP, POP3, IMAP, SSH, etc.)
             |
             v
Identify and safely validate security weaknesses
(cleartext traffic, weak authentication, misconfiguration)
             |
             v
Document evidence, impact, and remediation
```

**What to record:** tested hostname/IP, date, scope approval, the exact command and relevant output, uncertainty, potential impact, and a practical recommendation. **Avoid publishing live credentials, secrets, private data, or TryHackMe flags** in a public repository.

## 9. Final Takeaways

- **Start with passive recon** to understand what is publicly exposed before making direct contact.
- **Active recon verifies** hosts and services but can be detected and must remain within scope.
- **DNS describes service locations and configuration;** it is not proof of asset ownership or vulnerability.
- **Know your protocols:** HTTP for web traffic; FTP for files; SMTP for sending mail; POP3/IMAP for retrieving and synchronizing mail.
- **Learn to read service conversations**, not just memorize command names and port numbers.
- **Plaintext protocols risk exposing sensitive data** to an observer in the traffic path.
- **TLS and SSH protect communications**, but weak passwords and application vulnerabilities still matter.
- **Recon findings are leads, not confirmed vulnerabilities.** Validate carefully and communicate what you can actually prove.

## 10. Glossary

| Term | Definition |
|---|---|
| **OSINT** | Intelligence collected from publicly available information |
| **Attack surface** | Systems, applications, accounts, and interfaces that could be targeted |
| **Banner grabbing** | Reading a service's initial messages or response headers for information |
| **DNS resolver** | Service that looks up DNS answers on behalf of a client |
| **Authoritative DNS server** | Server that holds answers for a particular DNS zone |
| **CDN** | Content Delivery Network, often serving a website through globally distributed edge servers |
| **CT log** | Public record of issued TLS certificates |
| **ICMP** | Internet Control Message Protocol; used by tools such as `ping` |
| **TTL (IP)** | Packet hop limit that routers decrement |
| **TTL (DNS)** | Time a DNS record can be cached |
| **Banner** | Service-identifying information sent by a server |
| **Sniffing** | Capturing and examining network packets |
| **MITM** | Man-in-the-Middle: interception or modification of communication between parties |
| **TLS** | Transport Layer Security, used to protect data in transit |
| **STARTTLS** | Mechanism for upgrading an existing application-protocol connection to TLS |
| **SSH** | Encrypted protocol for remote access and related operations |
| **MFA** | Multi-Factor Authentication: requires an additional type of verification |

---

## Official Room References

1. [TryHackMe — Passive Reconnaissance](https://tryhackme.com/room/passiverecon)
2. [TryHackMe — Active Reconnaissance](https://tryhackme.com/room/activerecon)
3. [TryHackMe — Protocols and Servers](https://tryhackme.com/room/protocolsandservers)
4. [TryHackMe — Protocols and Servers 2](https://tryhackme.com/room/protocolsandservers2)
5. [TryHackMe — Network Reconnaissance module](https://tryhackme.com/module/network-reconnaissance)

*Personal study notes organized from the learning objectives of the TryHackMe rooms and general protocol knowledge. Example outputs and commands are illustrative, not records of specific lab results. No answer keys or flags are included.*
