# 🛡️ SOC Playbook: Triaging Azure AD Credential Compromise
**Scenario:** Microsoft Sentinel flags an "Impossible Travel" alert combined with a "Suspicious Inbox Forwarding Rule" creation for a corporate user.

### Step 1: Detection & Log Validation (Microsoft Sentinel)
My first goal is to validate if this is a True Positive or a VPN misconfiguration. I query the `SigninLogs` to analyze the anomalous IP address and compare the user agent strings against the user's baseline.
```kql
SigninLogs
| where UserPrincipalName == "compromised.user@company.com"
| where ResultType == "0" // Successful logins only
| project TimeGenerated, IPAddress, Location, UserAgent, AppDisplayName
| sort by TimeGenerated desc
```

### Step 2: Impact Analysis (Threat Hunting)
Once the compromised login is validated, I immediately pivot to `OfficeActivity` to determine what the attacker accessed and if data exfiltration is being prepared via forwarding rules.
```kql
OfficeActivity
| where UserId == "compromised.user@company.com"
| where Operation in ("New-InboxRule", "Set-Mailbox", "FileDownloaded")
| project TimeGenerated, Operation, Parameters, ClientIP
```

### Step 3: Containment & Remediation (Defender XDR / Entra ID)
Upon confirming malicious activity (e.g., an inbox rule forwarding emails to an external domain), I execute the following containment steps:
1. **Revoke Sessions:** Force-revoke all active Entra ID session tokens.
2. **Reset Credentials:** Trigger a mandatory password reset for the user.
3. **Disable Rules:** Remove the malicious Exchange Online forwarding rule.
4. **Escalate:** Document the timeline, IP IOCs (Indicators of Compromise), and accessed files, then escalate to Tier 2/Incident Response for further forensic review.
