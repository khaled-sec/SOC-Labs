**Category:** Threat Detection / SIEM Engineering

**Tools Used :** Splunk Enterprise 9.2.2, THC-Hydra, Windows Security Event Logs, FTP

**MITRE ATT&CK:**T1110 – Brute Force

**Date:** April 1, 2026

## Scenario

A SOC analyst needs to detect brute-force login attempts on Windows hosts. The goal is to build a Splunk detection rule that flags accounts with 5+ login attempts — including failures followed by a success — within a 5-minute window, and trigger a real-time High-severity alert.

Step 1: Configure Data Receiving on Port 9997

In Splunk, go to Settings → Forwarding and receiving → Add new under "Configure receiving". Enter port `9997` and click Save.

!image.png

**Step 2: Enable and Configure SplunkForwarder App**

Go to Apps → Manage Apps. Enable the SplunkForwarder app, then edit its properties and set Visible to Yes. Restart Splunk from Settings → Server controls.

!image.png

Step 3: Run the SPL Detection Query

Open SplunkForwarder app and run this query in the search bar:

index=* (EventCode=4624 OR EventCode=4625) | bin _time span=5m as minute | stats count(Keywords) as Attempts, count(eval(match(Keywords,"Audit Failure"))) as Failed, count(eval(match(Keywords,"Audit Success"))) as Success by minute Account_Name | where Attempts>=5 AND Success>0 AND Failed>=2 | eval minute=strftime(minute,"%H:%M")

!image.png

**Step 4: Create the Alert**

Click Save As → Alert and fill in:

- Title: `Failed Login Attempts`
- Description: `More than 5 failed login attempts are identified`
- Permissions: Private
- Alert type: Real-time

!image.png

**Step 5: Configure Throttle Settings**

Enable Throttle, set suppress field to `Account_Name`, suppress duration to `2 minutes`. Add action → Add to Triggered Alerts → Severity: High → Save.

!image.png

**Step 6: Execute Brute-Force Attack with Hydra**

On the Attacker Machine, open terminal and run:

sudo su
cd thc-hydra
hydra -L '/root/Wordlist/userlist.txt' -P '/root/Wordlist/pass.txt' ftp://10.10.10.12

!image.png

**Step 8: Verify FTP Access with Cracked Credentials**

Open a new terminal and run:

bash

`ftp 10.10.10.12`

Login with `administrator` / `Pa$$w0rd` to confirm successful access.

!image.png

**Step 9: Verify Alert Triggered in Splunk**

Switch to Analyst Machine 1. Go to Activity → Triggered Alerts (app: SplunkForwarder). Confirm the `Failed Login Attempts` alert appears.

!image.png

---

**Step 10: View Alert Results**

Click View Result on the triggered alert to inspect the flagged accounts and login attempt counts.

!image.png

## Key Findings

- **Event IDs 4624 / 4625** are the core detection signals for Windows authentication abuse
- **Throttling by `Account_Name`** prevents alert storms during active attacks
