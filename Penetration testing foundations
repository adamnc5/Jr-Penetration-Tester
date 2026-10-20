# 02 — Penetration Testing Foundations

> **TryHackMe · Jr Penetration Tester**  
> **Status:** Completed · **Rooms:** 5  
> **Type:** Personal technical notes — concepts, workflow, tools, and lessons (not a flag walkthrough)

[← Back to the pathway overview](../README.md)

## Overview

A **penetration test (pentest)** is an **authorized security assessment** in which a tester attempts to identify and, where appropriate, safely validate weaknesses in systems, applications, or networks. The goal is not merely to gain access; it is to show **what could go wrong, why it matters, and how to fix it**.

This module introduces the pentesting mindset through two guided engagements, then explains risk, ethics, the **Cyber Kill Chain**, and professional **testing methodologies**.

### Rooms covered

| Room | Main focus |
|---|---|
| [Guided Pentest: Web](https://tryhackme.com/room/guidedpentestnn) | Web enumeration, IDOR, password-reset flaws, upload validation, remote code execution |
| [Guided Pentest: Infrastructure](https://tryhackme.com/room/guidedpentestinfrastructure) | Service discovery, exploit research, initial access, privilege escalation, reporting |
| [Dive Into Pentesting](https://tryhackme.com/room/diveintopentesting) | Scope, risk, ethics, testing mindset, professional habits |
| [Cyber Kill Chain](https://tryhackme.com/room/cyberkillchain) | Seven stages of an intrusion and where defenders can stop it |
| [Penetration Testing Frameworks](https://tryhackme.com/room/penetrationtestingframeworks) | OSSTMM, OWASP WSTG, NIST SP 800-115, PTES, ISSAF, MITRE ATT&CK |

---

## 1. Guided Pentest: Web

**Lab context:** The fictional **RecruitX** recruitment portal. The assessment starts with very little knowledge of the application and demonstrates how a series of seemingly separate weaknesses can lead to server-side code execution.

### 1.1 Understand the attack surface first

Before testing vulnerabilities, map the application:

1. **Identify network services:** Which ports are open? Is the app running HTTP/HTTPS? What web server is in use?
2. **Inspect HTTP responses:** Headers can reveal software, session cookies, redirects, and other useful clues.
3. **Explore pages and functions:** Logins, registration, user profiles, admin features, file uploads, and password-reset flows.
4. **Discover less obvious paths:** Directories and API endpoints may exist even when they are not linked from the homepage.
5. **Observe how the application identifies data:** URL parameters, request bodies, cookies, and API responses.

**Commands used in the lab** (replace `LAB_IP` with a machine you are explicitly allowed to test):

```bash
# Scan all TCP ports; attempt service detection and default scripts
nmap -sV -sC -p- LAB_IP

# Inspect HTTP response headers
curl -I http://LAB_IP

# Discover web paths using a local wordlist
gobuster dir -u http://LAB_IP \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt \
  -x php

# Look at a known public API entry point
curl http://LAB_IP/api/
```

**Command details:**

| Option | Meaning |
|---|---|
| `-sV` | Probe services to identify likely software and versions |
| `-sC` | Run Nmap's default script set |
| `-p-` | Scan all 65,535 TCP ports (rather than only the common defaults) |
| `curl -I` | Request HTTP headers rather than the full page body |
| `gobuster dir` | Try candidate paths from a wordlist to find accessible web resources |
| `-x php` | Include `.php` extensions in directory/file discovery |

**Important distinction:** Finding a `/admin` directory or an API endpoint is **not itself proof of a vulnerability**. It becomes a security issue if the resource exposes information or functions to someone who should not have access.

### 1.2 Insecure Direct Object Reference (IDOR)

An **IDOR** occurs when an application lets the user select an object (such as a profile, order, or file) using an identifier but **fails to check authorization for that specific object**.

**Simple example:** A user visits `/profile.php?id=6` to see their own profile. Changing the parameter to `id=1` should **not** reveal someone else's private information merely because that record exists.

- **Authentication:** *Who are you?* (Are you logged in?)
- **Authorization:** *Are you allowed to access this particular record?*
- **Root cause:** Missing or incorrect **server-side object-level access control**.
- **Potential impact:** Exposure of private information and, when combined with other flaws, account takeover.
- **Fix:** Check the authenticated user's permission on **every** request to a protected object, including API endpoints. Do not rely on hidden buttons or unguessable IDs as the sole defense.

### 1.3 Weak password-reset logic

Password resets are security-sensitive because they can replace normal login authentication.

The lab illustrates why a reset process becomes dangerous when it **exposes a reset token in the response**, uses a **small token space**, and does **not sufficiently restrict guesses**.

A secure reset process should:

- Deliver the token through a channel controlled by the account owner (rather than displaying it to other requesters).
- Use cryptographically secure, high-entropy, unpredictable tokens.
- Give tokens a short lifetime, bind them to the intended account, and invalidate them after use.
- Rate-limit requests and verification attempts; avoid unnecessary account enumeration.
- Invalidate affected sessions or notify the owner when appropriate.

**Key idea:** Knowing an email address should not be enough to reset that person's password.

### 1.4 Admin access and unsafe file uploads

After gaining administrative access in the exercise, the application exposes a file-upload feature. The upload form uses the HTML `accept` attribute to guide which files a browser allows users to select.

However, **client-side restrictions are not security controls**: the request can be altered, so the server must validate the file independently.

The lab also demonstrates why an extension **blocklist** can fail: it may reject `.php` but overlook another extension that the web server treats as executable code.

**Safer design:**

- Allow only a small, explicit list of required file types (**allowlist**).
- Check extension **and** actual file format/content; do not trust the supplied MIME type alone.
- Rename stored files, limit size, and store uploads outside the public executable web root where possible.
- Configure upload directories so uploaded content **cannot execute as server-side code**.
- Apply least privilege, malware scanning when appropriate, and access controls.

### 1.5 Remote Code Execution (RCE) and vulnerability chaining

**Remote Code Execution (RCE)** means an attacker can cause code or operating-system commands to run on a target remotely. In this room, an unsafe upload that the server executes becomes the final step of the chain.

```text
Map services and application
          ↓
Find an object-level authorization weakness (IDOR)
          ↓
Discover account information
          ↓
Abuse an insecure password-reset process
          ↓
Access administrative functionality
          ↓
Bypass weak file-upload validation
          ↓
Server executes uploaded code (RCE)
```

**Why the chain matters:** An exposed profile and a weak reset flow are already vulnerabilities, but their **combined impact** is much greater than evaluating either in isolation.

**RCE does not automatically equal root access.** The executed process normally runs with the permissions of its application or service account. Further privilege escalation would require another weakness.

**What to remember:** Enumerate patiently, test authorization server-side, inspect password recovery and uploads, and always ask how one finding changes the impact of another.

---

## 2. Guided Pentest: Infrastructure

**Lab context:** An infrastructure assessment of a Linux host. Unlike the web exercise, the entry point here is a **network service** rather than an application workflow.

### 2.1 The infrastructure pentest workflow

```text
Enumeration → Vulnerability analysis → Initial access
            → Post-exploitation / privilege escalation → Reporting
```

| Phase | Question to answer | Output |
|---|---|---|
| Enumeration | What ports, services, versions, and configurations exist? | Service inventory and evidence |
| Vulnerability analysis | Which findings could be weaknesses? | Researched, prioritized hypotheses |
| Initial access | Can a weakness be safely validated within scope? | Proof of impact or a tested finding |
| Post-exploitation | What access exists, and what is its potential impact? | Privilege/context information |
| Reporting | How does the client reproduce and fix the issue? | Findings, evidence, remediation |

### 2.2 Enumerating services with Nmap

```bash
nmap -sV -sC -oN scan.txt LAB_IP
```

- `-sV`: Identify service versions.
- `-sC`: Run default scripts for additional service information.
- `-oN scan.txt`: Save readable output. Keeping scan results makes findings easier to compare and report later.

**Interpret the results rather than blindly trusting them.** An open port suggests a service is accessible. A version string provides a research lead, but it **does not prove** a vulnerability exists. Verify applicability, configuration, and behavior.

### 2.3 Researching possible vulnerabilities

The lab uses an **IRC service (UnrealIRCd)** to show how an identified service can be researched for a known flaw.

```bash
# Research public exploit references on the lab workstation
searchsploit unrealircd
```

Useful research questions:

1. Does the version and build actually match the advisory?
2. Does the exploit depend on a particular configuration, operating system, or feature?
3. What access does it require, and what result should it produce?
4. Is verification allowed by the rules of engagement?
5. Could testing cause a service interruption?

**Tools:** `SearchSploit` searches a local copy of Exploit-DB references. **Metasploit** provides modules for vulnerability testing and exploitation, but modules still require careful configuration and authorization.

### 2.4 Metasploit concepts

```text
msfconsole                # Open the Metasploit console
search unrealircd         # Find related modules
use <module>              # Select a module
show options              # Inspect required settings
show payloads             # View compatible payload types
set RHOSTS LAB_IP         # Set the authorized target
```

| Term | Meaning |
|---|---|
| **Exploit** | Method or module that uses a specific weakness |
| **Payload** | What runs or happens if exploitation succeeds |
| **RHOSTS** | Remote target host(s) |
| **RPORT** | Remote target service port |
| **LHOST** | Local address used by some payloads/listeners |
| **Session / shell** | An interaction channel with the target after access is established |

**Initial access (foothold)** means obtaining some access to a system. That access may be limited: a low-privilege shell is not equivalent to full system control.

### 2.5 Post-exploitation and privilege escalation

Once access exists, local enumeration can reveal the permissions of the current user and security misconfigurations.

```bash
whoami            # Current account
id                # User ID and group memberships
hostname          # Machine name
uname -a          # Kernel/system information
find / -iname '*password*' 2>/dev/null  # Locate filenames matching a pattern
```

**Why `2>/dev/null`?** `2` is the standard-error stream. Redirecting it to `/dev/null` hides permission-denied messages and similar errors, leaving the search results easier to read.

The exercise demonstrates a serious configuration mistake: a low-privilege user can find **privileged credentials stored in readable plaintext**, leading to higher-level access. That is an example of **privilege escalation**: moving from an account with fewer privileges to one with more.

**Defensive lessons:**

- Never store privileged passwords in unprotected plaintext files.
- Rotate exposed secrets immediately and audit where they were used.
- Restrict file permissions and implement least privilege.
- Disable unnecessary remote access and protect privileged login paths.
- Use appropriate secrets management and secure authentication methods.

### 2.6 Reporting: the professional deliverable

A penetration test is useful only if the findings can help someone fix the system.

A good report includes:

1. **Executive summary** — plain-language risk and business impact.
2. **Scope and methodology** — tested systems, dates, constraints, and approach.
3. **Findings prioritized by severity** — so teams know what to address first.
4. **Technical evidence** — reproducible observations without unnecessarily exposing secrets.
5. **Remediation** — specific steps for reducing the risk.
6. **Limitations and retest results**, when relevant.

**Example finding (illustrative):**

| Field | Example |
|---|---|
| Title | Privileged credentials stored in readable plaintext |
| Impact | A low-privilege user could obtain administrator credentials |
| Evidence | Restricted, redacted file-location and permission details |
| Root cause | Improper secret storage and access controls |
| Recommendation | Remove/rotate credentials, restrict access, implement secrets management |

**What to remember:** Discovery leads to research, research leads to carefully scoped validation, and findings lead to concrete fixes.

---

## 3. Dive Into Pentesting

### 3.1 Pentesting versus malicious hacking

The same technical capability can be used for good or harm; what distinguishes professional pentesting is **explicit permission, an agreed scope, responsible execution, and reporting**.

Before starting, confirm:

- **Authorization:** Who has formally approved the assessment?
- **Scope:** Which IP addresses, applications, accounts, and locations are included or excluded?
- **Rules of engagement:** Which techniques, hours, or impact levels are permitted?
- **Communication:** Who should be contacted if testing affects a system or uncovers sensitive data?
- **Deliverables:** What evidence and report does the client expect?

A publicly reachable target is **not** automatically authorized for testing.

### 3.2 Main areas of testing

| Area | Typical questions |
|---|---|
| **Web application** | Can users access others' data? Are sessions, inputs, and uploads secure? |
| **Network / infrastructure** | Which services are reachable? Are they vulnerable, misconfigured, or unnecessarily exposed? |
| **Authentication** | Can accounts be taken over or permissions bypassed? |
| **Privilege boundaries** | Can an account gain permissions it should not have? |

### 3.3 Vulnerability, threat, and risk

- **Asset:** Something worth protecting, such as customer information or a production server.
- **Vulnerability:** A weakness, such as missing access control.
- **Threat:** A potential source or event that could exploit a weakness.
- **Impact:** The damage if exploitation occurs.
- **Risk:** The likelihood of a harmful event together with its possible impact.

The room uses the simplified relationship **Vulnerability × Threat = Risk** to explain that a weakness matters in the context of a plausible threat. In professional assessments, risk evaluation also considers exposure, exploitability, affected assets, and business consequences; it is **not a literal universal equation**.

**Example:** A forgotten administrator password in a public file is a vulnerability. Someone discovering and abusing it is a threat scenario. Unauthorized access to confidential data is the possible impact.

### 3.4 Basic risk management cycle

1. **Identify** assets, threats, and vulnerabilities.
2. **Assess** likelihood, impact, and priority.
3. **Treat** the risk by mitigating, avoiding, transferring, or consciously accepting it.
4. **Monitor and review** whether controls remain effective.

Risk **acceptance** is a deliberate decision by the appropriate owner, not a reason to ignore an issue.

### 3.5 Why vulnerabilities exist

Common causes include:

- Software defects and insecure design choices.
- Misconfigurations and weak default settings.
- Human error or mistaken assumptions about user behavior.
- Complex systems and unexpected interactions between components.
- Excessively customized or outdated environments.
- Missing access controls, insecure dependencies, or insufficient testing.

### 3.6 The mindset of a good pentester

- **Be curious:** A small inconsistency may point to a bigger weakness.
- **Think in context:** Understand the application, users, assets, and business impact.
- **Don't depend on one tool:** Automated scans produce leads, not complete conclusions.
- **Avoid tunnel vision:** If a hypothesis fails, revisit enumeration rather than forcing an exploit.
- **Take notes as you go:** Record commands, timestamps, observations, and evidence.
- **Minimize harm:** Respect testing limits and stop/escalate unexpected impact.
- **Communicate clearly:** Explain risks and fixes, not just technical tricks.

---

## 4. Cyber Kill Chain

The **Lockheed Martin Cyber Kill Chain** divides a common intrusion pattern into seven stages. It is useful to attackers for understanding an attack path and, especially, to defenders for identifying **where the chain can be interrupted**.

### The seven stages

| # | Stage | Meaning | Illustrative defender response |
|---|---|---|---|
| 1 | **Reconnaissance** | Collect information about the target | Reduce unnecessary exposure; monitor scanning and suspicious information gathering |
| 2 | **Weaponization** | Prepare a malicious capability or payload | Threat intelligence; defensive planning and hardening |
| 3 | **Delivery** | Get the capability or lure to the target | Email filtering, safe browsing, attachment controls |
| 4 | **Exploitation** | Trigger a weakness to gain execution or access | Patch systems, protect applications, exploit prevention |
| 5 | **Installation** | Install malware or another means of continued access | Endpoint detection, application controls, persistence monitoring |
| 6 | **Command and Control (C2)** | Communicate with and direct a compromised system | Detect suspicious outbound connections, DNS/network monitoring |
| 7 | **Actions on Objectives** | Carry out the goal: e.g., steal data or disrupt services | Limit privileges, detect exfiltration, segment networks, incident response |

### Differences worth remembering

- **Weaponization vs. Delivery:** Preparing a malicious attachment is not the same as sending it.
- **Delivery vs. Exploitation:** Reaching a user's inbox does not mean code has executed.
- **Exploitation vs. Installation:** Running through a vulnerability does not automatically mean persistence has been established.
- **Installation vs. C2:** A foothold on the machine is different from a channel to remotely control it.
- **C2 vs. Actions on Objectives:** Remote control is often a means to an end, not the final objective.

### Example scenario

```text
Gather employee contact details        → Reconnaissance
Prepare a malicious attachment         → Weaponization
Send the attachment                    → Delivery
A vulnerability is triggered           → Exploitation
A backdoor is placed on the system     → Installation
The backdoor calls an attacker server  → Command and Control
Sensitive data is copied out           → Actions on Objectives
```

**Limitations:** Real attacks are not always linear. Some stages are skipped, repeated, or occur in a different order, especially in cloud or identity-based attacks. Use the Kill Chain as a **mental model**, not a rule that every intrusion must follow perfectly.

---

## 5. Penetration Testing Frameworks

A **pentest methodology/framework** makes testing systematic. It helps testers avoid gaps, remain inside scope, communicate results consistently, and give clients understandable evidence.

### 5.1 Key frameworks compared

| Framework | What it emphasizes | Useful for |
|---|---|---|
| **OSSTMM** — Open Source Security Testing Methodology Manual | Structured, measurable assessment of operational security across channels | Broad security testing requiring consistent measurement |
| **OWASP WSTG** — Web Security Testing Guide | Detailed web application testing categories and test cases | Web apps, APIs, authentication, sessions, inputs |
| **NIST SP 800-115** | Planning, technical security assessment, findings, mitigation | Organizational security testing and formal assessment programs |
| **PTES** — Penetration Testing Execution Standard | The practical end-to-end lifecycle of an engagement | General professional pentests |
| **ISSAF** — Information Systems Security Assessment Framework | Detailed information-systems assessment methodology | Historical reference and structured technical assessments |
| **MITRE ATT&CK** | Observed adversary **tactics and techniques** | Threat emulation, detection coverage, mapping attacker behavior |

**Important:** MITRE ATT&CK is a **knowledge base**, not a complete client-engagement process like PTES. The Cyber Kill Chain is an **attack lifecycle model**, not a replacement for scoping and reporting.

### 5.2 PTES: the seven engagement phases

PTES provides a particularly useful workflow to remember:

1. **Pre-engagement interactions:** Agree on goals, scope, authorization, and rules.
2. **Intelligence gathering:** Learn about the systems and attack surface.
3. **Threat modeling:** Determine which assets and attacker scenarios matter most.
4. **Vulnerability analysis:** Identify and validate weaknesses.
5. **Exploitation:** Demonstrate impact within the approved boundaries.
6. **Post-exploitation:** Understand the consequences of access while minimizing risk.
7. **Reporting:** Explain findings, evidence, severity, and remediations.

### 5.3 OWASP WSTG: what to examine in a web app

Examples of important categories include:

- Information gathering and technology fingerprinting.
- Configuration and deployment security.
- Identity management, authentication, and authorization.
- Session management.
- Input validation and injection weaknesses.
- Error handling, cryptography, and business logic.
- Client-side behavior and API-related exposure.

**Connection to the web lab:** IDOR belongs to **authorization testing**; password recovery belongs to **authentication testing**; dangerous uploads involve **input/file handling and server configuration**.

### 5.4 NIST SP 800-115: a simple three-phase view

1. **Planning:** Establish goals, scope, roles, methods, and constraints.
2. **Execution:** Conduct technical assessments and validate findings appropriately.
3. **Post-execution:** Analyze evidence, explain causes, recommend mitigations, and report.

### 5.5 OSSTMM and ISSAF

- **OSSTMM:** Emphasizes repeatable testing and measurement of operational security across areas such as **human, physical, wireless, telecommunications, and data networks**. Useful when consistent scope and measurement matter.
- **ISSAF:** A more detailed, historically influential assessment framework. Useful for understanding how structured technical checks can fit inside a larger assessment process.

### 5.6 MITRE ATT&CK: tactics vs. techniques

- **Tactic = why** the adversary performs an action (for example, *Credential Access*).
- **Technique = how** the goal is achieved (for example, a particular method of credential theft).
- **Sub-technique = a more specific method**.

**Use together:** PTES explains **how to run and report a pentest**; MITRE ATT&CK helps explain **which adversary behaviors were tested or observed**.

### 5.7 Other frameworks worth recognizing

The room also introduces several more specialized references. They are not interchangeable with an end-to-end pentest methodology:

- **WASC Threat Classification:** A vocabulary for describing classes of web application security issues.
- **CSA Cloud Controls Matrix (CCM):** Security control guidance for cloud environments.
- **OWASP Mobile Application Security Testing Guide (MASTG):** Technical guidance for assessing mobile applications.
- **PCI DSS penetration testing guidance:** Testing expectations in environments that handle payment-card data.
- **CBEST:** Threat-intelligence-led security testing in the UK financial sector.

These become relevant when the engagement has a specific technology, industry, or regulatory context.

### 5.8 Choosing a methodology

| Engagement | Good starting point |
|---|---|
| Assess a web application | **OWASP WSTG** plus a full engagement process such as PTES |
| Run an end-to-end internal network pentest | **PTES** |
| Plan a formal security assessment | **NIST SP 800-115** |
| Measure operational security across multiple channels | **OSSTMM** |
| Emulate known attacker behaviors and assess detection | **MITRE ATT&CK**, alongside an engagement methodology |

Different standards can **complement**, rather than compete with, each other.

---

## Quick Reference

### Commands from the guided exercises

> **Only use against TryHackMe lab machines or other explicitly authorized systems.** Commands here are learning references; a tool's presence in a lab does not imply permission to use it elsewhere.

```bash
# Network/service enumeration
nmap -sV -sC -oN scan.txt LAB_IP
nmap -sV -sC -p- LAB_IP

# Web enumeration
curl -I http://LAB_IP
gobuster dir -u http://LAB_IP -w /path/to/wordlist.txt -x php

# Vulnerability research
searchsploit unrealircd

# Local Linux context (after authorized access)
whoami
id
hostname
uname -a
find / -iname '*password*' 2>/dev/null
```

| Tool | Purpose |
|---|---|
| **Nmap** | Port scanning, service enumeration, and basic network discovery |
| **curl** | Send HTTP requests and inspect responses |
| **Gobuster** | Discover candidate web paths via wordlists |
| **SearchSploit** | Search local Exploit-DB references for known vulnerabilities |
| **Metasploit** | Select, configure, and run security-testing modules in a controlled assessment |
| **Browser Developer Tools** | Inspect page markup, requests, cookies, and client-side behavior |

### Glossary

| Term | Short definition |
|---|---|
| **Scope** | The assets and testing activities explicitly permitted |
| **Attack surface** | Exposed components that could potentially be attacked |
| **Enumeration** | Collecting concrete information about a system and its services |
| **Foothold / initial access** | The first successful access to a target |
| **IDOR** | Access-control flaw allowing unauthorized object access through direct references |
| **RCE** | Ability to execute code or commands remotely on a target |
| **Privilege escalation** | Gaining permissions beyond those initially available |
| **Payload** | Code or an action delivered or run after an exploit is triggered |
| **C2** | Command-and-control communication with a compromised system |
| **Remediation** | Changes that remove or reduce an identified risk |

## Final Takeaways

1. **Start with permission and scope.** Technical ability alone does not authorize testing.
2. **Enumerate before attempting exploitation.** Good observations lead to better hypotheses.
3. **A tool result is a clue, not a finding.** Check context and confirm impact.
4. **Chained vulnerabilities matter.** Weaknesses that seem small in isolation can create serious consequences together.
5. **Distinguish access levels.** An application account, a low-privilege shell, and root access are not the same thing.
6. **Use frameworks to stay systematic.** PTES and OWASP WSTG complement practical testing.
7. **Document the result and the fix.** Evidence and remediation make a pentest valuable.

---

## Sources and Further Reading

**TryHackMe rooms:**

- [Guided Pentest: Web](https://tryhackme.com/room/guidedpentestnn)
- [Guided Pentest: Infrastructure](https://tryhackme.com/room/guidedpentestinfrastructure)
- [Dive Into Pentesting](https://tryhackme.com/room/diveintopentesting)
- [Cyber Kill Chain](https://tryhackme.com/room/cyberkillchain)
- [Penetration Testing Frameworks](https://tryhackme.com/room/penetrationtestingframeworks)

**Standards / references:**

- [OWASP Web Security Testing Guide](https://owasp.org/projects/web-security-testing-guide)
- [NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [OSSTMM (ISECOM)](https://www.isecom.org/OSSTMM.3.pdf)

*Notes are paraphrased for personal study. Lab examples are intentionally limited to concepts and representative commands, not flags, secrets, or step-by-step room answers.*
