# Splunk Use Case: Brute-Force Detection & Alerting
**Category:** Threat Detection / SIEM Engineering

**Tools Used:** Splunk Enterprise 9.2.2, THC-Hydra, Windows Security Event Logs, FTP

**MITRE ATT&CK:** T1110 – Brute Force

**Date:** April 1, 2026

## Scenario

A SOC analyst needs to detect brute-force login attempts on Windows hosts. The goal is to build a Splunk detection rule that flags accounts with **5+ login attempts** — including failures followed by a success — within a **5-minute window**, then trigger a **High Severity** real-time alert.

---

## Step 1: Configure Data Receiving on Port 9997

In Splunk, navigate to:

**Settings → Forwarding and Receiving → Configure Receiving → Add New**

Configure port **9997** and save.

![](assets/image%201.png)

---

## Step 2: Enable SplunkForwarder

Go to:

**Apps → Manage Apps**

Enable **SplunkForwarder**, set **Visible = Yes**, then restart Splunk.

![](assets/image%202.png)

---

## Step 3: Run the SPL Detection Query

```spl
index=* (EventCode=4624 OR EventCode=4625)
| bin _time span=5m as minute
| stats count(Keywords) as Attempts,
        count(eval(match(Keywords,"Audit Failure"))) as Failed,
        count(eval(match(Keywords,"Audit Success"))) as Success
        by minute Account_Name
| where Attempts>=5 AND Success>0 AND Failed>=2
| eval minute=strftime(minute,"%H:%M")
```

![](assets/image%203.png)

---

## Step 4: Create the Alert

Save the search as an alert with the following settings:

* **Title:** Failed Login Attempts
* **Description:** More than 5 failed login attempts are identified
* **Permissions:** Private
* **Alert Type:** Real-time

![](assets/image%204.png)

---

## Step 5: Configure Alert Throttling

Configure:

* Suppress Field → `Account_Name`
* Suppress Period → **2 Minutes**
* Severity → **High**

![](assets/image%205.png)

---

## Step 6: Execute the Brute-Force Attack

Run Hydra from the attacker machine:

```bash
sudo su
cd thc-hydra
hydra -L '/root/Wordlist/userlist.txt' -P '/root/Wordlist/pass.txt' ftp://10.10.10.12
```

![](assets/image%206.png)

---

## Step 7: Verify FTP Access

Connect to the FTP server using the discovered credentials.

```bash
ftp 10.10.10.12
```

Credentials:

* Username: `administrator`
* Password: `Pa$$w0rd`

![](assets/image%207.png)

---

## Step 8: Verify the Triggered Alert

Go to:

**Activity → Triggered Alerts**

Verify that the alert **Failed Login Attempts** has been triggered.

![](assets/image%208.png)

---

## Step 9: Review Alert Results

Open **View Results** and review the detected account along with the login statistics.

![](assets/image%210.png)

---

## Key Findings

- Event IDs 4624 / 4625 are primary indicators for Windows authentication activity.
- Correlating failed and successful logins within a time window improves brute-force detection.
- Alert throttling using Account_Name prevents duplicate alerts.
- Splunk can generate real-time detections using SPL correlation searches.

---

## What I Learned

- Built a real-time Splunk detection rule using SPL.
- Correlated Windows authentication events (4624/4625) to detect brute-force attacks.
- Configured alert throttling to reduce duplicate alerts.
- Validated the detection by simulating a real attack with Hydra.
- Mapped the detection to MITRE ATT&CK (T1110 – Brute Force).

---

## Skills Demonstrated

- SPL Query Development
- SIEM Alert Engineering
- Windows Security Log Analysis
- Brute Force Detection
- MITRE ATT&CK Mapping
- Alert Tuning (Throttling)
