# SOC Lab Setup Guide
**Author:** Vivek Katkade | SOC Analyst

## Overview
This guide provides step-by-step instructions to set up a Security Operations Center (SOC) lab using VMware, Splunk, Wazuh, and a custom Python alert notifier. The lab consists of three VMs: SIEM-Server (Ubuntu), Windows-Victim, and Kali-Attacker.

---

## 1. SIEM-Server (Ubuntu 22.04)
**IP:** 192.168.56.10 | **RAM:** 2GB | **Role:** Splunk + Wazuh

### 1.1. Ubuntu Installation
- Create a new VM in VMware Workstation Pro.
- Assign Ubuntu 22.04 ISO, 2GB RAM, 1 CPU, 20GB disk.
- Set network to Host-Only (192.168.56.0/24).

### 1.2. Splunk Installation
- Download Splunk 9.2.0 from [splunk.com](https://www.splunk.com/en_us/download.html).
- Install Splunk:
	```bash
	sudo dpkg -i splunk-9.2.0.deb
	sudo /opt/splunk/bin/splunk start --accept-license
	```
- Access Splunk Web: http://192.168.56.10:8000

### 1.3. Wazuh Installation
- Follow [Wazuh quickstart guide](https://documentation.wazuh.com/current/installation-guide/index.html).
- Install Wazuh Manager:
	```bash
	curl -s https://packages.wazuh.com/install.sh | sudo bash
	```
- Verify Wazuh dashboard: https://192.168.56.10:55000

### 1.4. Python Alert Notifier
- Ensure Python 3.x is installed:
	```bash
	sudo apt update && sudo apt install python3 python3-pip
	```
- Place `soc_alert_notifier.py` in `/opt/soc/` or desired directory.
- Install dependencies (if any):
	```bash
	pip3 install -r requirements.txt
	```
- Configure script to monitor Wazuh/Splunk alerts.

---

## 2. Windows-Victim (Windows 10 Pro)
**IP:** 192.168.56.20 | **RAM:** 2GB | **Role:** Monitored endpoint

### 2.1. Windows Installation
- Create a new VM in VMware Workstation Pro.
- Assign Windows 10 ISO, 2GB RAM, 1 CPU, 40GB disk.
- Set network to Host-Only (192.168.56.0/24).

### 2.2. Wazuh Agent Installation
- Download Wazuh agent from [wazuh.com](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent.html).
- Install agent and configure to connect to SIEM-Server (192.168.56.10).

### 2.3. Log Forwarding
- Enable Windows Event Forwarding to Wazuh.
- Confirm logs are visible in Wazuh/Splunk dashboards.

---

## 3. Kali-Attacker (Kali Linux)
**IP:** 192.168.56.30 | **RAM:** 2GB | **Role:** Attack simulation

### 3.1. Kali Installation
- Create a new VM in VMware Workstation Pro.
- Assign Kali Linux ISO, 2GB RAM, 1 CPU, 20GB disk.
- Set network to Host-Only (192.168.56.0/24).

### 3.2. Attack Tools
- Use built-in Kali tools (nmap, metasploit, etc.) to simulate attacks.
- Generate traffic/events for detection by SIEM-Server.

---

## 4. Lab Validation
- Confirm all VMs can ping each other.
- Verify Splunk and Wazuh dashboards show alerts/logs.
- Test Python notifier for alert delivery.

---

## 5. Troubleshooting
- Check network settings (Host-Only, correct IPs).
- Review logs in Splunk, Wazuh, and Python script.
- Restart services if needed.

---

## References
- [Splunk Documentation](https://docs.splunk.com/Documentation/Splunk)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Kali Linux Tools](https://tools.kali.org/)
