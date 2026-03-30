# Log Management — Exercises Overview

Log Management — Exercises Overview

**Category:** SOC Analysis | Windows Logging | Web Application Security

**Platform:** EC-Council Lab Environment

**Date:** March 2026

---

## Summary

This document covers two hands-on exercises focused on configuring, monitoring, and analyzing logs in a Windows environment. The goal was to understand how logs serve as a primary detection source for a SOC analyst, and how real attacks leave traceable evidence in those logs.

---

## What I Learned

- Windows does not log failed logins by default — audit policy must be configured proactively
- IIS logs every web request including attack payloads in the URL query string
- Event ID 4625 with Logon Type 8 is a strong indicator of an FTP brute force attack
- SQL Injection attempts are URL-encoded in IIS logs but remain detectable
- XML/XPath filters in Event Viewer allow precise correlation similar to real SIEM queries

---

## Exercises

| # | Title | Attack Simulated | Key Tool | Key Log/Event |
| --- | --- | --- | --- | --- |
| 1 | Windows Local Logging | FTP Brute Force | Hydra | Event ID 4625 — Logon Type 8 |
| 2 | IIS Log Monitoring | SQL Injection | Browser (manual) | IIS W3C Log — cs-uri-query |
|  |  |  |  |  |

## Exercise 1 — Windows Local Logging

**Objective:** Configure Windows audit policy and detect a brute force attack via Event Viewer.

**Attack:** Used Hydra from an Ubuntu attacker machine to brute force an FTP server on a Windows target at `10.10.10.12`. Successfully recovered credentials: `Administrator / Pa$$w0rd`.

**Detection:** Filtered Event Viewer Security logs for Event ID 4625 with Logon Type 8 using an XPath query — confirming the brute force pattern.

View Full Documentation:

[Exercise 1 — Windows Local Logging](./Exercise_1_Windows_Local_Logging.md)

## Exercise 2 — IIS Log Monitoring

**Objective:** Configure IIS logging fields and detect a SQL Injection attack from log files.

**Attack:** Logged into the LuxuryTreats web application as user `bob`, then modified the order URL to inject `' or 1=1;--`, which returned all orders from all users in the database.

**Detection:** Navigated to `C:\inetpub\logs\LogFiles\W3SVC2` and opened the log file in Notepad. Found the URL-encoded payload `%27+or+1%3d1%3b--` confirming the injection attempt was recorded.

 View Full Documentation:

[Exercise 2 — IIS Log Monitoring](./Exercise_2_IIS_Log_Monitoring.md)

---

## Environment

| Component | Details |
| --- | --- |
| Target Machine | Windows Server 2022 |
| Attacker Machine | Ubuntu (VirtualBox) |
| Tools Used | Hydra, Event Viewer, IIS Manager, Notepad |
| Log Sources | Windows Security Log, IIS W3C Log |
