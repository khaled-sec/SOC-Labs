# Exercise 2: Local Logging: Configuring, Monitoring, and Analyzing IIS Logs

Internet Information Services (IIS) is a web server for Windows server that hosts anything (Content or Services) on the Web. Monitoring IIS logs can give insight about user activities detect any anomalous behavior. IIS logs can be examined to understand potential security breaches.

**Lab Scenario**

IIS log file provides useful information regarding the person who visited your site, what information is viewed and when it is viewed, the activity of various web applications, etc. As a SOC analyst, the information in IIS logs can help you to detect threats on the web applications.

**Lab Objectives**

The objective of this lab is to help students learn how to configure, view, and analyze logs in IIS.

**Overview of IIS Log Monitoring**

Monitoring IIS logs is essential for SOC analysts to understand user activities, track web application performance, and identify anomalous behavior that may indicate security breaches. These logs provide valuable insights into who visited the site, what content was accessed, and when. By analyzing IIS logs, analysts can detect potential threats and enhance the security of web applications.

step 1 :Configure IIS Logging on Windows Server

Navigate to:

`Start → Administrative Tools → Internet Information Services (IIS) Manager`

![image.png](image%206.png)

![image.png](image%207.png)

 click **WEBSERVER2022**

![image.png](image%208.png)

go to logging in IIS 

![image.png](image%209.png)

Expand the **WEBSERVER2022** node, then expand **Sites**. You will see three hosted sites:

![image.png](image%2010.png)

In the Logging pane, you can see:

- **Format:** W3C (standard IIS log format)
- **Log file location:** `%SystemDrive%\inetpub\logs\LogFiles`
- **Log Event Destination:** Log file only

![image.png](image%2011.png)

Click **Select Fields** to verify which fields are being logged. The following fields were confirmed enabled:

| Field | Description |
| --- | --- |
| s-ip | Server IP address |
| cs-method | HTTP method (GET, POST) |
| cs-uri-stem | The page requested |
| cs-uri-query | Query string in the URL |
| sc-status | HTTP response status code |
| c-ip | Client IP address |
| cs(User-Agent) | Browser/tool making the request |

![image.png](image%2012.png)

![image.png](image%2013.png)

save all change and close the  **Internet Information Service (IIS) Manager** and **Administrative Tools** window

Step 2:Simulate Attack from Attacker Machine

Switch to the attacker machine (Ubuntu). Open Firefox and navigate to:

`http://www.luxurytreats.com`

Log in using the following credentials:

- **Username:** bob
- **Password:** Passw0rd

![image.png](image%2014.png)

![image.png](image%2015.png)

Go to **My Orders** and click on order **ORD-001** to view its details. The normal URL will be:

`http://www.luxurytreats.com/OrderDetail.aspx?Id=ORD-001`

![image.png](image%2016.png)

![image.png](image%2017.png)

![image.png](image%2018.png)

Now perform a SQL Injection by modifying the URL to:

[http://www.luxurytreats.com/OrderDetail.aspx?Id=ORD-001](http://www.luxurytreats.com/OrderDetail.aspx?Id=ORD-001) ' or 1=1;--

**What this does:** The `' or 1=1;--` payload breaks out of the SQL query and adds a condition that is always true. Because the application does not validate user input before passing it to the database, the query returns all rows from the Orders table — exposing data belonging to other users.

![image.png](image%2019.png)

This trick will fetch the order details of the other users.

![image.png](image%2020.png)

step 3 :Analyze IIS Logs on Windows Server

Switch back to the Windows Server machine. Open **File Explorer** and navigate to:

`C:\inetpub\logs\LogFiles\W3SVC2`

The folder **W3SVC2** contains log files for the **LuxuryTreats** site (Site ID 2). Open the most recent log file with **Notepad**.

![image.png](image%2021.png)

![image.png](image%2022.png)

Inside the log file, search for the SQL Injection attempt by looking for `1=1` in the entries. You will find a line similar to:

`2026-03-28 11:42:35 10.10.10.12 GET /OrderDetail.aspx Id=ORD-001%27+or+1%3d1%3b-- 80 bob 10.10.10.56 Mozilla/5.0...`

Note that the SQL Injection characters are URL-encoded in the log:

- `%27` = `'` (single quote)
- `%3d` = `=`
- `%3b` = `;`
- This confirms the attack was recorded by IIS and is visible in the log file.

![image.png](image%2023.png)

### Analysis & Findings

The IIS log clearly captured the SQL Injection attempt. Key indicators visible in the log:

- The exact URL payload used
- The timestamp of the attack
- The HTTP method used (GET)
- The target page

This demonstrates that even when an application is vulnerable, IIS logs provide a full audit trail that allows a SOC analyst to detect, investigate, and respond to the attack.

### 💡 Lessons Learned

1. **IIS logs every request by default** — Unlike Windows Event Viewer which requires audit policy configuration, IIS logging is enabled out of the box. However, confirming the right fields are enabled (especially `cs-uri-query`) is essential for capturing attack payloads.
2. **SQL Injection leaves clear traces in IIS logs** — The payload `' or 1=1;--` gets URL-encoded but is still readable and searchable. A SOC analyst should know the encoded forms of common attack characters.
3. **The `cs-uri-query` field is critical** — Without this field enabled, the query string (where the injection payload lives) would not be logged, making detection impossible.
4. **Log file location matters** — IIS stores logs per-site under `C:\inetpub\logs\LogFiles\W3SVC[SiteID]`. Knowing this path lets analysts quickly find the right logs during an incident.
5. **Input validation is the root cause** — The attack succeeded because the application passed user input directly to the database query without sanitization. From a SOC perspective, this is a finding that should be escalated to the development team.
6. **W3C format is industry standard** — The W3C log format used by IIS is the same format understood by most SIEM tools, making it easy to ingest and correlate these logs in a real SOC environment