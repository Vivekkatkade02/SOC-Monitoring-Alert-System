Architectural 


# 🏗️ SOC Lab Architecture
**Author:** Vivek Katkade | SOC Analyst

## Network Diagram
```
┌──────────────────────────────────────────────────────────────┐
│               VMware Host-Only Network: 192.168.56.0/24      │
│                                                              │
│  ┌─────────────────┐    ┌──────────────────┐                │
│  │   Kali Linux    │    │   Windows 10     │                │
│  │  192.168.56.30  │    │  192.168.56.20   │                │
│  │  [Attacker]     │    │  [Victim]        │                │
│  └────────┬────────┘    └────────┬─────────┘                │
│           │  Attack traffic      │  Windows logs            │
│           └──────────┬───────────┘                          │
│                      ▼                                       │
│           ┌──────────────────────┐                          │
│           │   Ubuntu 22.04       │                          │
│           │   192.168.56.10      │                          │
│           │   [SIEM Server]      │                          │
│           │                      │                          │
│           │  ┌────────────────┐  │                          │
│           │  │  Wazuh Manager │  │  ← Detects threats       │
│           │  └────────────────┘  │                          │
│           │  ┌────────────────┐  │                          │
│           │  │    Splunk      │  │  ← Visualises alerts     │
│           │  └────────────────┘  │                          │
│           │  ┌────────────────┐  │                          │
│           │  │ Python Monitor │  │  ← Sends notifications   │
│           │  └────────────────┘  │                          │
│           └──────────────────────┘                          │
└──────────────────────────────────────────────────────────────┘
```

## VM Specifications
| VM | OS | IP | RAM | Role |
|----|----|----|-----|------|
| SIEM-Server | Ubuntu 22.04 | 192.168.56.10 | 2GB | Splunk + Wazuh |
| Windows-Victim | Windows 10 Pro | 192.168.56.20 | 2GB | Monitored endpoint |
| Kali-Attacker | Kali Linux | 192.168.56.30 | 2GB | Attack simulation |

## Tech Stack
| Tool | Version | Purpose |
|------|---------|---------|
| Splunk | 9.2.0 | SIEM & log visualisation |
| Wazuh | 4.7.x | IDS & alert engine |
| VMware Workstation Pro | 17+ | Virtual lab environment |
| Python | 3.x | Custom alert notifier |