# SOC Labs — Hands-On Cybersecurity Documentation

**Author:** Khaled Al-Mohammadi  
**Goal:** SOC Analyst | Threat Hunter  
**Certifications:** Security+ | Network+ | CySA+ | eJPT | eCTHP *(in progress)*

---

## About This Repository

This repository documents hands-on cybersecurity labs covering real-world 
attack scenarios and detection techniques. Each module simulates threats 
a SOC analyst encounters on the job — from log analysis to network forensics 
and threat hunting.

All labs are performed in isolated lab environments using industry-standard 
tools aligned with MITRE ATT&CK.

---

## Lab Modules

| # | Module | Topics | Status |
|---|--------|--------|--------|
| 01 | [Log Management](./01-Log-Management/README.md) | FTP Brute Force, SQL Injection, IIS Logs, Event Viewer, XPath Filters | ✅ Complete |
| 02 | Network Analysis | Wireshark, Nmap, TCP Flags, Packet Analysis | 🔄 In Progress |
| 03 | SIEM — Wazuh | Alert Triage, Custom Rules, Dashboard | 🔄 In Progress |
| 04 | Threat Hunting | MITRE ATT&CK, YARA Rules, IOC Analysis | 🔜 Coming Soon |
| 05 | CTF Writeups | LetsDefend, CyberDefenders Challenges | 🔜 Coming Soon |

---

## Tools & Technologies

| Category | Tools |
|----------|-------|
| SIEM | Wazuh, Splunk |
| Network | Wireshark, Nmap |
| Offensive | Hydra, Metasploit |
| Windows | Event Viewer, IIS Manager |
| Frameworks | MITRE ATT&CK, Cyber Kill Chain |

---

## Lab Environment

- **Virtualization:** VirtualBox
- **Attacker Machine:** Ubuntu
- **Target Machines:** Windows Server 2022
- **Platform:** EC-Council Lab Environment
