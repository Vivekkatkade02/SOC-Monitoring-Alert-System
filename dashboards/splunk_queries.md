Splunk 

# 📊 Splunk SPL Queries — SOC Monitoring & Alert System
**Author:** Vivek Katkade | SOC Analyst  
**Tool:** Splunk Enterprise / Splunk Free  
**Dashboard:** Security Operations Center (SOC)

---

## 🔰 HOW TO USE THESE QUERIES

```
1. Open Splunk Web UI  →  http://192.168.56.10:8000
2. Click  Search & Reporting
3. Paste any query below into the search bar
4. Adjust time range as needed (default: Last 24 hours)
5. Save as Dashboard Panel for real-time monitoring
```

---

## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## SECTION 1 — AUTHENTICATION & LOGIN EVENTS
## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### 1.1 — All Failed SSH Login Attempts (Last 24 Hours)
```spl
index=* sourcetype=syslog "Failed password" earliest=-24h
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "for (?:invalid user )?(?P<username>\S+) from"
| stats count AS failed_attempts BY src_ip, username
| sort - failed_attempts
| rename src_ip AS "Source IP", username AS "Target User",
         failed_attempts AS "Failed Attempts"
```

---

### 1.2 — Brute Force Detection (10+ Failures from Same IP)
```spl
index=* sourcetype=syslog "Failed password" earliest=-1h
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| bucket _time span=1m
| stats count AS attempts BY _time, src_ip
| where attempts > 10
| sort - attempts
| eval threat_level = case(
    attempts > 50, "CRITICAL",
    attempts > 20, "HIGH",
    attempts > 10, "MEDIUM",
    true(),        "LOW"
  )
| table _time, src_ip, attempts, threat_level
```

---

### 1.3 — Successful Logins (Who Logged In & When)
```spl
index=* sourcetype=syslog "Accepted password" OR "Accepted publickey"
| rex field=_raw "for (?P<username>\S+) from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count AS login_count, 
        values(src_ip) AS source_ips,
        min(_time) AS first_login,
        max(_time) AS last_login BY username, host
| eval first_login = strftime(first_login, "%Y-%m-%d %H:%M:%S")
| eval last_login  = strftime(last_login,  "%Y-%m-%d %H:%M:%S")
| sort - login_count
```

---

### 1.4 — Successful Login AFTER Multiple Failures (Compromise Indicator!)
```spl
index=* sourcetype=syslog earliest=-1h
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval event_type = case(
    like(_raw, "%Failed password%"),   "FAILURE",
    like(_raw, "%Accepted password%"), "SUCCESS",
    true(), "OTHER"
  )
| where event_type IN ("FAILURE", "SUCCESS")
| stats 
    count(eval(event_type="FAILURE")) AS failures,
    count(eval(event_type="SUCCESS")) AS successes
    BY src_ip
| where failures > 5 AND successes > 0
| eval risk = "⚠️ POSSIBLE COMPROMISE"
| sort - failures
```

---

### 1.5 — Root Login Attempts
```spl
index=* sourcetype=syslog user=root OR "for root from"
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval status = case(
    like(_raw, "%Accepted%"), "SUCCESS ✅",
    like(_raw, "%Failed%"),   "FAILED ❌",
    true(), "UNKNOWN"
  )
| table _time, host, src_ip, status
| sort - _time
```

---

## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## SECTION 2 — NETWORK RECONNAISSANCE
## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### 2.1 — Port Scan Activity Detection
```spl
index=* sourcetype=syslog (nmap OR "port scan" OR "SYN" OR "ACK scan" OR "XMAS")
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count AS scan_events, 
        values(_raw) AS raw_events
        BY src_ip, host
| where scan_events > 5
| sort - scan_events
| eval alert = "🔴 PORT SCAN DETECTED"
```

---

### 2.2 — Firewall Blocked Connections (Top Blocked IPs)
```spl
index=* sourcetype=syslog (DROPPED OR REJECTED OR "firewall block") earliest=-1h
| rex field=_raw "SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "DPT=(?P<dst_port>\d+)"
| stats count AS blocked_count BY src_ip, dst_ip, dst_port
| sort - blocked_count
| head 20
```

---

### 2.3 — Unusual Outbound Connections (Suspicious Ports)
```spl
index=* sourcetype=syslog earliest=-1h
| rex field=_raw "DPT=(?P<dst_port>\d+)"
| where dst_port IN ("4444","1337","31337","6666","9999","8888","2222")
| rex field=_raw "SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| rex field=_raw "DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+)"
| eval port_label = case(
    dst_port="4444",  "Metasploit Default",
    dst_port="1337",  "Hacker Port",
    dst_port="31337", "Back Orifice",
    dst_port="6666",  "IRC/Botnet",
    true(), "Suspicious"
  )
| table _time, src_ip, dst_ip, dst_port, port_label
| sort - _time
```

---

## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## SECTION 3 — SYSTEM & FILE CHANGES
## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### 3.1 — Critical System File Modifications
```spl
index=* sourcetype=syslog ("/etc/passwd" OR "/etc/shadow" OR 
        "/etc/sudoers" OR "/etc/ssh/sshd_config" OR "authorized_keys")
| eval severity = case(
    like(_raw, "%shadow%"),       "CRITICAL — Password hashes",
    like(_raw, "%sudoers%"),      "CRITICAL — Sudo config",
    like(_raw, "%authorized_keys%"), "CRITICAL — SSH backdoor risk",
    like(_raw, "%sshd_config%"),  "HIGH — SSH config",
    like(_raw, "%passwd%"),       "HIGH — User accounts",
    true(), "MEDIUM"
  )
| table _time, host, severity, _raw
| sort - _time
```

---

### 3.2 — New User Account Creation
```spl
index=* sourcetype=syslog ("useradd" OR "new user" OR "adduser") earliest=-24h
| rex field=_raw "name=(?P<new_user>\S+)"
| table _time, host, new_user, _raw
| sort - _time
```

---

### 3.3 — Sudo Command Usage Tracking
```spl
index=* sourcetype=syslog "sudo" earliest=-24h
| rex field=_raw "(?P<username>\w+) : TTY=\S+ ; PWD=(?P<directory>\S+) ; USER=(?P<run_as>\S+) ; COMMAND=(?P<command>.+)"
| table _time, host, username, run_as, command, directory
| sort - _time
```

---

## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## SECTION 4 — WAZUH ALERT ANALYSIS
## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### 4.1 — All Wazuh Alerts (Last Hour)
```spl
index=wazuh earliest=-1h
| eval severity = case(
    rule_level >= 12, "🔴 CRITICAL",
    rule_level >= 10, "🟠 HIGH",
    rule_level >= 7,  "🟡 MEDIUM",
    rule_level >= 4,  "🟢 LOW",
    true(),           "⚪ INFO"
  )
| table _time, severity, rule_level, rule_description, agent_name, full_log
| sort - rule_level
```

---

### 4.2 — Wazuh Alert Count by Agent (Who is Most Active?)
```spl
index=wazuh earliest=-24h
| stats count AS total_alerts,
        max(rule_level) AS max_level
        BY agent_name
| eval status = if(max_level >= 10, "⚠️ NEEDS ATTENTION", "✅ Normal")
| sort - total_alerts
```

---

### 4.3 — Top 10 Triggered Rule IDs
```spl
index=wazuh earliest=-24h
| stats count AS trigger_count BY rule_id, rule_description
| sort - trigger_count
| head 10
| rename rule_id AS "Rule ID",
         rule_description AS "Description",
         trigger_count AS "Times Triggered"
```

---

### 4.4 — Wazuh Alerts Over Time (Trend Chart)
```spl
index=wazuh earliest=-24h
| bucket _time span=30m
| eval severity = case(
    rule_level >= 12, "Critical",
    rule_level >= 10, "High",
    rule_level >= 7,  "Medium",
    true(),           "Low"
  )
| stats count BY _time, severity
| timechart span=30m count BY severity
```
> 💡 **Visualise as:** Area Chart or Line Chart in Splunk

---

## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## SECTION 5 — WINDOWS EVENT LOG QUERIES
## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### 5.1 — Windows Failed Logins (Event ID 4625)
```spl
index=wineventlog EventCode=4625 earliest=-24h
| stats count AS failed_count BY src_ip, user, host, Logon_Type
| where failed_count > 3
| eval logon_type_desc = case(
    Logon_Type=2,  "Interactive",
    Logon_Type=3,  "Network",
    Logon_Type=10, "RemoteInteractive (RDP)",
    true(),        "Other"
  )
| sort - failed_count
```

---

### 5.2 — Windows Event Log Cleared (Anti-Forensics! Event ID 1102)
```spl
index=wineventlog EventCode=1102
| table _time, host, user, message
| eval alert = "🚨 SECURITY LOG CLEARED — INVESTIGATE IMMEDIATELY"
| sort - _time
```

---

### 5.3 — New Windows User Account Created (Event ID 4720)
```spl
index=wineventlog EventCode=4720 earliest=-7d
| table _time, host, src_user, user, message
| sort - _time
```

---

### 5.4 — Windows Privilege Escalation (Event ID 4672)
```spl
index=wineventlog EventCode=4672 earliest=-24h
| where user != "SYSTEM" AND user != "LOCAL SERVICE"
| stats count BY user, host
| sort - count
```

---

## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## SECTION 6 — SOC OVERVIEW DASHBOARD
## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### 6.1 — Total Alert Count by Severity (Last 24hrs) — KPI Panel
```spl
index=wazuh earliest=-24h
| eval severity = case(
    rule_level >= 12, "Critical",
    rule_level >= 10, "High",
    rule_level >= 7,  "Medium",
    true(),           "Low"
  )
| stats count BY severity
| sort - count
```
> 💡 **Visualise as:** Single Value or Pie Chart

---

### 6.2 — Top 10 Source IPs Generating Alerts
```spl
index=* earliest=-24h
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| where isnotnull(src_ip)
| stats count AS alert_count BY src_ip
| sort - alert_count
| head 10
```
> 💡 **Visualise as:** Bar Chart

---

### 6.3 — Alert Timeline (Last 6 Hours)
```spl
index=wazuh earliest=-6h
| timechart span=10m count AS alerts
```
> 💡 **Visualise as:** Line Chart — shows attack spikes clearly

---

### 6.4 — Geographic Source of Attacks (IP Lookup)
```spl
index=* sourcetype=syslog "Failed password" earliest=-24h
| rex field=_raw "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| iplocation src_ip
| stats count AS attacks BY Country, src_ip
| sort - attacks
| head 15
```

---

## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## SECTION 7 — INCIDENT RESPONSE QUERIES
## ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### 7.1 — Full Activity Timeline for a Suspicious IP
```spl
| Replace 1.2.3.4 with the actual suspicious IP |
index=* "1.2.3.4" earliest=-24h
| table _time, host, sourcetype, _raw
| sort + _time
```

---

### 7.2 — All Events from a Specific Agent (Endpoint Investigation)
```spl
index=wazuh agent_name="Windows-Victim" earliest=-24h
| table _time, rule_level, rule_description, full_log
| sort - rule_level
```

---

### 7.3 — Commands Run by a Specific User (Audit Trail)
```spl
index=* sourcetype=syslog "vivek" earliest=-7d
| rex field=_raw "COMMAND=(?P<command>.+)"
| where isnotnull(command)
| table _time, host, command
| sort + _time
```

---

## 📌 QUICK REFERENCE — SPL CHEAT SHEET

| Command | Purpose |
|---------|---------|
| `index=*` | Search all indexes |
| `sourcetype=syslog` | Filter by log type |
| `earliest=-24h` | Last 24 hours |
| `\| stats count BY field` | Group and count |
| `\| rex field=_raw "pattern"` | Extract fields with regex |
| `\| eval x = case(...)` | Conditional field creation |
| `\| timechart span=1h count` | Time-based chart |
| `\| sort - count` | Sort descending |
| `\| head 10` | Top 10 results |
| `\| table field1, field2` | Display specific columns |
| `\| where count > 5` | Filter results |
| `\| iplocation src_ip` | GeoIP lookup |