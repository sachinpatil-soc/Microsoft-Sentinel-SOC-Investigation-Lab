
# 🔍 KQL Threat Hunting Queries

- The following KQL queries simulate common investigations performed by Enterprise SOC Analysts using Microsoft Sentinel.

- These queries focus on authentication monitoring, brute-force detection, suspicious login behavior, and incident triage.

## Query 1 — Top Attacking IP Addresses

### Objective

Identify IP addresses responsible for the highest number of failed RDP authentication attempts.

### KQL Query

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, Computer, AccountType, FailureReason
| where FailedAttempts >= 10
| order by FailedAttempts desc
```

### Investigation Result

![Top Attacking IPs](screenshots/query1-top-attacking-ip.png)

### Analyst Observation

Two external IP addresses generated a significant number of failed authentication attempts against the Azure honeypot. This activity is consistent with automated brute-force or password spraying attacks and would require further investigation in a production SOC environment.
---

## Query 2 — Most Targeted User Accounts

### Objective

Identify which user accounts received the highest number of failed authentication attempts.

### KQL Query

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| summarize FailedAttempts = count() by TargetAccount
| sort by FailedAttempts desc
```

### Investigation Result

![Most Targeted Accounts](https://github.com/sachinpatil-soc/Microsoft-Sentinel-Lab/blob/40487555fa41c51901286153ca2896effe97d6a5/screenshots/query2-Most%20Targeted%20Usernames.png)

### Analyst Observation

The investigation identified the accounts most frequently targeted during the brute-force activity. The built-in **Administrator** account received the highest number of failed login attempts, which is consistent with common attacker behavior targeting privileged accounts.

---

## Query 3 — Failed Authentication Activity Over Time

### Objective

Visualize failed authentication attempts over time to identify attack spikes and periods of increased malicious activity.

### KQL Query

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| summarize FailedAttempts = count() by bin(TimeGenerated, 1h)
| render timechart
```

### Investigation Result

![Failed Authentication over time](https://github.com/sachinpatil-soc/Microsoft-Sentinel-Lab/blob/2e4df078eec0700771b59b9ac7edb960726ad639/screenshots/query3-Failed%20Authentication%20Over%20Time.png)

### Analyst Observation

The time-series visualization highlights periods of increased brute-force activity against the Internet-facing Windows server. Monitoring authentication trends helps analysts correlate attack activity with other security events during an investigation.

---

## Query 4 — Successful Logons

### Objective

Identify successful authentication events during the monitoring period.

### KQL Query

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| summarize SuccessfulLogons = count() by Account, IpAddress
| sort by SuccessfulLogons desc
```

### Investigation Result

![Successful Logons](https://github.com/sachinpatil-soc/Microsoft-Sentinel-Lab/blob/4e6b632bd673cf7bb842ea1666b064ea36bbd792/screenshots/query4-Successful%20Logins%20(4624).png)

### Analyst Observation

The investigation verified whether any successful authentication events occurred during the monitoring period. Correlating successful logons with previous authentication failures is an important SOC investigation step.

---
## Query 5 - Top Targeted Computers

### Objective 

Identify which systems received the highest volume of failed authentication attempts.

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| summarize FailedAttempts = count() by Computer
| order by FailedAttempts desc
```

### Investigation Results 

![Top Targeted Computer](https://github.com/sachinpatil-soc/Microsoft-Sentinel-Lab/blob/a69984099e7b58a3aba700599545808ab55d74a4/screenshots/query5-Top%20Targeted%20Computers.png)

### Analyst Observation

The investigation identified the computers that received the highest volume of failed authentication attempts during the monitoring period. This helps the analyst spot likely targeted systems and investigate repeated Event ID 4625 activity for possible brute-force attempts, credential issues, or misconfigured services

---
## Query 6 Logon Type

### Objective

Determine which Windows logon types attackers attempted to use.

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| summarize FailedAttempts = count() by LogonType
| order by FailedAttempts desc
```
### Investigation Results 

![logon type](https://github.com/sachinpatil-soc/Microsoft-Sentinel-Lab/blob/de5f6652443d0e4bbd81f564020ef2745ea8810e/screenshots/query6-Logon%20Types.png)

### Analyst Observation

Identified authentication patterns by logon type to detect abnormal access methods. Unusual remote or privileged logons may indicate credential misuse or unauthorized access attempts.

---

## Query 7 Failed Logins by Hour 

### Objective
 Identify peak attack hours.

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| summarize FailedAttempts = count() by LogonType
| order by FailedAttempts desc
```

### Investigation Results

![Failed Logins by Hour](https://github.com/sachinpatil-soc/Microsoft-Sentinel-Lab/blob/e1637d09b59412208cb7b6b3edf1c1ba0d7fdc9b/screenshots/query7-Failed%20Logins%20by%20Hour.png)


### Analyst Observation:

Analyzed failed login activity by time to identify brute-force or password-spraying patterns. Login spikes during unusual hours require further investigation.

---

## Query 8 Top Failure Reasons

### Objective
Identify the most common authentication failure reasons.

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| summarize FailedAttempts = count() by FailureReason
| order by FailedAttempts desc
```

### Investigation Results
![Top Failure Reason](https://github.com/sachinpatil-soc/Microsoft-Sentinel-Lab/blob/90986dbba6c05fd636c008559df1982e0ac63dea/screenshots/query8-Top%20Failure%20Reasons.png)


### Analyst Observation:

Reviewed authentication failure reasons to identify common user errors and potential attack activity. Repeated failures may indicate credential-based threats.

---

## Query 9 MUltiple Usernames From Same IP

### Objective 
Detect password-spraying behavior by identifying IP addresses attempting multiple user accounts.

```kql
SecurtyEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| summarize TargetedUsers = dcount (TargetAccount) by IpAddress
| where TargetedUsers >= 5
| order by TargetedUsers Desc
```

### Investigation Results

![Multipal Usersname Same Ip](https://github.com/sachinpatil-soc/Microsoft-Sentinel-Lab/blob/a2a93317f1303516f0383aa0fc663682c559931e/screenshots/query9-Multiple%20Usernames%20From%20Same%20IP.png)


### Analyst Observation:
Detected IP addresses attempting authentication against multiple accounts, which may indicate password spraying, credential stuffing, or compromised hosts.

---

## Query 10 Attacker to Target Account Mapping

### Objective

Map attacker IP addresses to the user accounts they attempted to authenticate against during the investigation period. This helps distinguish targeted brute-force attacks from password spraying activity.

```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| summarize FailedAttemts = count () by IpAddress, TargetAccount
| where FailedAttemts >= 10
| sort by failedAttemts desc
```

### Investigation Results

![Attacker to target account](https://github.com/sachinpatil-soc/Microsoft-Sentinel-Lab/blob/5b83000169685b94341a93183ae9a893ae66b0dd/screenshots/query10-Attacker%20to%20Target%20Account%20Mapping.png)


### Analyst Observations

This query correlates source IP addresses with the user accounts they attempted to access. IP addresses targeting multiple accounts may indicate password spraying activity, while repeated attempts against a single account are more consistent with targeted brute-force attacks. This information provides valuable context for SOC analysts when determining attack patterns and escalation requirements.









