incident detection and triage  
## Exercise 1: Splunk Brute-Force Detection Use Case

**Objective:** Detect brute-force login attempts using Windows Security Events and generate real-time alerts in Splunk SIEM.

**Key Steps:**

- Configure Splunk to receive logs on port 9997
- Write an SPL query to detect 5+ login attempts with failures followed by a success
- Create a real-time alert with High severity
- Simulate a brute-force attack using Hydra against an FTP target
- Verify the alert fires and surfaces the compromised accounts

**MITRE ATT&CK:**
T1110 – Brute Force

**Tools Used:**
Splunk Enterprise, THC-Hydra, Windows Security Event Logs

**Detection Query:**

```
index=* (EventCode=4624 OR EventCode=4625)
| bin _time span=5m as minute
| stats count(Keywords) as Attempts,
        count(eval(match(Keywords,"Audit Failure"))) as Failed,
        count(eval(match(Keywords,"Audit Success"))) as Success
        by minute Account_Name
| where Attempts>=5 AND Success>0 AND Failed>=2
| eval minute=strftime(minute,"%H:%M")
```

📄 Full Lab Writeup →

Splunk Use Case: Brute-Force Detection & Alerting

---
