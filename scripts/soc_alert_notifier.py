#!/usr/bin/env python3
"""
=====================================================================
  SOC Alert Notifier — Real-Time Wazuh Alert Monitor
  Author  : Vivek Katkade
  Role    : SOC Analyst
  Stack   : Python 3, Wazuh, Splunk
  Description:
      Monitors Wazuh's alerts.json log file in real time,
      parses incoming alerts, classifies by severity, prints
      colour-coded console output, and sends email notifications
      for HIGH / CRITICAL level events.
=====================================================================
"""

import json
import time
import smtplib
import os
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# ─────────────────────────────────────────────
#  CONFIGURATION  — Edit these before running
# ─────────────────────────────────────────────
ALERT_LOG       = "/var/ossec/logs/alerts/alerts.json"
SMTP_SERVER     = "smtp.gmail.com"
SMTP_PORT       = 587
EMAIL_SENDER    = "soc-monitor@yourdomain.com"
EMAIL_PASSWORD  = "your_app_password_here"       # Use App Password for Gmail
EMAIL_RECIPIENT = "vivkekatkade@gmail.com"
MIN_ALERT_LEVEL = 7                              # Only process level 7+ alerts

# ─────────────────────────────────────────────
#  SEVERITY LEVELS
# ─────────────────────────────────────────────
SEVERITY = {
    "INFO"     : (1,  3),
    "LOW"      : (4,  6),
    "MEDIUM"   : (7,  9),
    "HIGH"     : (10, 11),
    "CRITICAL" : (12, 15),
}

# ANSI colour codes for terminal output
COLOURS = {
    "INFO"     : "\033[94m",   # Blue
    "LOW"      : "\033[92m",   # Green
    "MEDIUM"   : "\033[93m",   # Yellow
    "HIGH"     : "\033[91m",   # Red
    "CRITICAL" : "\033[95m",   # Magenta
    "RESET"    : "\033[0m",
}


def get_severity_label(level: int) -> str:
    """Return severity label string for a given numeric level."""
    for label, (low, high) in SEVERITY.items():
        if low <= level <= high:
            return label
    return "UNKNOWN"


def parse_alert(line: str) -> dict | None:
    """
    Parse a single JSON line from Wazuh alerts.json.
    Returns a normalised alert dict or None on parse failure.
    """
    try:
        raw = json.loads(line.strip())
        rule = raw.get("rule", {})
        agent = raw.get("agent", {})
        data = raw.get("data", {})

        return {
            "timestamp"   : raw.get("timestamp", datetime.now().isoformat()),
            "level"       : int(rule.get("level", 0)),
            "rule_id"     : rule.get("id", "N/A"),
            "description" : rule.get("description", "No description"),
            "groups"      : ", ".join(rule.get("groups", [])),
            "agent_name"  : agent.get("name", "Unknown"),
            "agent_ip"    : agent.get("ip", "N/A"),
            "src_ip"      : data.get("srcip", data.get("src_ip", "N/A")),
            "dest_ip"     : data.get("dstip", "N/A"),
            "user"        : data.get("dstuser", data.get("user", "N/A")),
            "full_log"    : raw.get("full_log", ""),
        }
    except (json.JSONDecodeError, ValueError, TypeError):
        return None


def print_alert(alert: dict) -> None:
    """Print a colour-coded alert banner to the console."""
    label  = get_severity_label(alert["level"])
    colour = COLOURS.get(label, COLOURS["RESET"])
    reset  = COLOURS["RESET"]

    print(f"""
{colour}╔══════════════════════════════════════════════════════╗
║   🚨  SOC ALERT  —  {label:<10}  (Level {alert['level']:>2})         ║
╠══════════════════════════════════════════════════════╣
║  Time        : {alert['timestamp'][:19]}
║  Rule ID     : {alert['rule_id']}
║  Description : {alert['description'][:50]}
║  Agent       : {alert['agent_name']} ({alert['agent_ip']})
║  Source IP   : {alert['src_ip']}
║  Dest IP     : {alert['dest_ip']}
║  User        : {alert['user']}
║  Groups      : {alert['groups'][:50]}
╚══════════════════════════════════════════════════════╝{reset}
    """)


def send_email_alert(alert: dict) -> None:
    """
    Send an HTML email notification for HIGH / CRITICAL alerts.
    Requires valid SMTP credentials in the config section above.
    """
    label = get_severity_label(alert["level"])

    subject = f"[SOC ALERT] {label} — Level {alert['level']} — {alert['description'][:60]}"

    html_body = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px;">
      <div style="background:#1a1a2e;color:white;padding:20px;border-radius:8px;">
        <h2 style="color:#e94560;">🚨 SOC ALERT TRIGGERED</h2>
        <table style="width:100%;border-collapse:collapse;">
          <tr><td style="padding:8px;color:#aaa;">Severity</td>
              <td style="padding:8px;color:#e94560;font-weight:bold;">{label} (Level {alert['level']})</td></tr>
          <tr><td style="padding:8px;color:#aaa;">Time</td>
              <td style="padding:8px;">{alert['timestamp'][:19]}</td></tr>
          <tr><td style="padding:8px;color:#aaa;">Rule ID</td>
              <td style="padding:8px;">{alert['rule_id']}</td></tr>
          <tr><td style="padding:8px;color:#aaa;">Description</td>
              <td style="padding:8px;">{alert['description']}</td></tr>
          <tr><td style="padding:8px;color:#aaa;">Agent</td>
              <td style="padding:8px;">{alert['agent_name']} ({alert['agent_ip']})</td></tr>
          <tr><td style="padding:8px;color:#aaa;">Source IP</td>
              <td style="padding:8px;">{alert['src_ip']}</td></tr>
          <tr><td style="padding:8px;color:#aaa;">User</td>
              <td style="padding:8px;">{alert['user']}</td></tr>
          <tr><td style="padding:8px;color:#aaa;">Groups</td>
              <td style="padding:8px;">{alert['groups']}</td></tr>
        </table>
        <p style="margin-top:20px;color:#aaa;font-size:12px;">
          Investigate immediately via your Splunk Dashboard at
          <a href="http://192.168.56.10:8000" style="color:#e94560;">
          http://192.168.56.10:8000</a>
        </p>
      </div>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = EMAIL_SENDER
    msg["To"]      = EMAIL_RECIPIENT
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        print(f"  📧  Email alert sent to {EMAIL_RECIPIENT}")
    except Exception as e:
        print(f"  ⚠️  Email failed: {e}")


def log_alert_to_file(alert: dict) -> None:
    """Append alert summary to a local CSV log for record keeping."""
    log_path = "/var/log/soc_alerts.csv"
    header   = "timestamp,level,severity,rule_id,description,agent,src_ip,user\n"
    row = (
        f"{alert['timestamp'][:19]},"
        f"{alert['level']},"
        f"{get_severity_label(alert['level'])},"
        f"{alert['rule_id']},"
        f"\"{alert['description']}\","
        f"{alert['agent_name']},"
        f"{alert['src_ip']},"
        f"{alert['user']}\n"
    )
    try:
        write_header = not os.path.exists(log_path)
        with open(log_path, "a") as f:
            if write_header:
                f.write(header)
            f.write(row)
    except PermissionError:
        pass  # Skip file logging if running without root


def monitor_alerts(min_level: int = MIN_ALERT_LEVEL) -> None:
    """
    Tail Wazuh alerts.json in real time.
    Processes every new line as it is written by Wazuh.
    """
    print(f"""
╔══════════════════════════════════════════════════════╗
║        🛡️  SOC Alert Notifier  —  STARTED            ║
║  Watching : {ALERT_LOG[:42]}
║  Min Level: {min_level}  ({get_severity_label(min_level)}+)
║  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
╚══════════════════════════════════════════════════════╝
    """)

    # Wait for log file to exist
    while not os.path.exists(ALERT_LOG):
        print(f"  ⏳  Waiting for {ALERT_LOG} ...")
        time.sleep(5)

    counters = {"total": 0, "medium": 0, "high": 0, "critical": 0}

    with open(ALERT_LOG, "r") as f:
        f.seek(0, 2)  # Jump to end of file (tail mode)

        while True:
            line = f.readline()

            if not line:
                time.sleep(0.5)
                continue

            alert = parse_alert(line)
            if not alert:
                continue

            if alert["level"] < min_level:
                continue

            counters["total"] += 1
            label = get_severity_label(alert["level"]).lower()
            if label in counters:
                counters[label] += 1

            # Print to console
            print_alert(alert)

            # Log to file
            log_alert_to_file(alert)

            # Send email for HIGH and CRITICAL
            if alert["level"] >= 10:
                send_email_alert(alert)

            # Print running stats every 10 alerts
            if counters["total"] % 10 == 0:
                print(f"  📊  Stats — Total: {counters['total']} | "
                      f"Medium: {counters['medium']} | "
                      f"High: {counters['high']} | "
                      f"Critical: {counters['critical']}")


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    # Allow overriding min level from CLI: python3 soc_alert_notifier.py 10
    level = int(sys.argv[1]) if len(sys.argv) > 1 else MIN_ALERT_LEVEL
    try:
        monitor_alerts(min_level=level)
    except KeyboardInterrupt:
        print("\n\n  🛑  SOC Monitor stopped by user.\n")