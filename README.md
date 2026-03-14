# Create README (copy-paste this into the file)
cat > README.md << 'EOF'
# 🛡️ SOC Monitoring & Alert System

A fully functional Security Operations Center (SOC) lab built 
to monitor, detect, and respond to cybersecurity threats in real time.

## 🏗️ Architecture
- **SIEM Server** : Ubuntu 22.04 + Splunk + Wazuh Manager
- **Victim Machine** : Windows 10 (Monitored endpoint)
- **Attacker Machine** : Kali Linux (Attack simulation)
- **Network** : VMware Host-Only (192.168.56.0/24)

## 🛠️ Tech Stack
| Tool | Purpose |
|------|---------|
| Splunk | Log aggregation & SIEM dashboard |
| Wazuh | Intrusion detection & alerting |
| Kali Linux | Attack simulation |
| VMware Workstation Pro | Virtual lab environment |
| Python | Custom alert notification script |

## 🚨 Features
- Real-time log monitoring from Windows & Linux endpoints
- Custom alert rules for brute force, port scans, root logins
- Python script for automated email notifications
- Splunk SPL dashboards for threat visualization
- Attack simulation using Hydra & Nmap

## 📁 Project Structure
- /docs → Architecture & setup documentation
- /scripts → Python alert notifier
- /rules → Custom Wazuh detection rules
- /dashboards → Splunk SPL queries

## ⚙️ Setup
See [docs/setup-guide.md](docs/setup-guide.md) for full 
step-by-step installation guide.

## 👤 Author
**Vivekanand Katkade**  
SOC Analyst | CEHv13 | CCNA  
EOF