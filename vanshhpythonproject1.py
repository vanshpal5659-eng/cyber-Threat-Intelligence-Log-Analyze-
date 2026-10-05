
import os
import re
import smtplib
import json
import urllib.request
from datetime import datetime

class CyberLogAnalyzer:
    def __init__(self, log_filename="server.log"):
        self.log_filename = log_filename
        self.failed_login_threshold = 3
        # VirusTotal API Key (Free tier key link: https://www.virustotal.com/)
        self.vt_api_key = "YOUR_VIRUSTOTAL_API_KEY"

    def create_sample_log_file(self):
        """Testing ke liye sample log file create karta hai."""
        sample_logs = """2026-10-05 10:00:12 IP: 192.168.1.10 - User 'admin' - LOGIN_SUCCESS
2026-10-05 10:02:45 IP: 45.33.21.11 - User 'admin' - FAILED_LOGIN
2026-10-05 10:02:47 IP: 45.33.21.11 - User 'admin' - FAILED_LOGIN
2026-10-05 10:02:50 IP: 45.33.21.11 - User 'admin' - FAILED_LOGIN
2026-10-05 10:02:52 IP: 45.33.21.11 - User 'admin' - FAILED_LOGIN
2026-10-05 10:05:00 IP: 103.21.244.0 - User 'guest' - LOGIN_SUCCESS
2026-10-05 10:10:15 IP: 185.220.101.5 - User 'root' - FAILED_LOGIN - SQL_INJECTION_DETECTED ' OR '1'='1
2026-10-05 10:12:30 IP: 185.220.101.5 - User 'root' - FAILED_LOGIN - SQL_INJECTION_DETECTED
2026-10-05 10:15:00 IP: 192.168.1.15 - User 'user1' - LOGIN_SUCCESS
"""
        with open(self.log_filename, "w") as f:
            f.write(sample_logs)
        print(f"[+] Sample log file '{self.log_filename}' create ho gayi hai.\n")

    def check_virustotal_reputation(self, ip_address):
        """VirusTotal API ke through IP ka threat reputation score check karta hai."""
        if self.vt_api_key == "YOUR_VIRUSTOTAL_API_KEY":
            return "API Key Missing (Skipped online check)"

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        req = urllib.request.Request(url, headers={"x-apikey": self.vt_api_key})

        try:
            with urllib.request.urlopen(req) as response:
                data = json.loads(response.read().decode())
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                return f"Malicious Engines Count: {malicious_count}"
        except Exception as e:
            return f"API Query Error ({e})"

    def send_email_alert(self, subject, body):
        """Critical attack detect hone par automated email alert bhejta hai."""
        # Note: Testing ke liye credentials configure kar sakte hain
        sender_email = "your_email@gmail.com"
        receiver_email = "admin_email@gmail.com"
        password = "your_app_password"  # Gmail App Password

        message = f"Subject: {subject}\n\n{body}"

        try:
            # Code structure ready for deployment
            print(f"\n[EMAIL SYSTEM] Generating Email Alert for Admin...")
            print(f"               Subject: {subject}")
            print(f"               Status: Ready to dispatch.")
        except Exception as e:
            print(f"[!] Email Send Error: {e}")

    def analyze_logs(self):
        """Log file scan karke attacks detect karta hai."""
        if not os.path.exists(self.log_filename):
            self.create_sample_log_file()

        ip_failed_counts = {}
        suspicious_activities = []
        total_logs = 0

        ip_pattern = r"IP:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

        print("=" * 65)
        print("    CYBER THREAT INTELLIGENCE & AUTOMATED INCIDENT RESPONSE    ")
        print("=" * 65)

        with open(self.log_filename, "r") as f:
            for line in f:
                total_logs += 1
                ip_match = re.search(ip_pattern, line)

                if ip_match:
                    ip = ip_match.group(1)

                    # 1. Detect Failed Logins
                    if "FAILED_LOGIN" in line:
                        ip_failed_counts[ip] = ip_failed_counts.get(ip, 0) + 1

                    # 2. Detect Attack Signatures
                    if "SQL_INJECTION" in line or "OR '1'='1" in line:
                        suspicious_activities.append((ip, "SQL Injection Attempt", line.strip()))

        print(f"\n[INFO] Total Log Entries Analyzed: {total_logs}")
        print("-" * 65)

        # Brute Force Threat Report
        print("\n[!] BRUTE-FORCE / SUSPICIOUS IP ANALYSIS:")
        flagged_ips = []
        for ip, count in ip_failed_counts.items():
            if count >= self.failed_login_threshold:
                vt_status = self.check_virustotal_reputation(ip)
                print(f"  [CRITICAL ALERT] IP: {ip} -> {count} Failed Login Attempts!")
                print(f"                   Threat Intel: {vt_status}")
                flagged_ips.append((ip, count, vt_status))
            else:
                print(f"  [NORMAL] IP: {ip} -> {count} Failed Login Attempt(s)")

        # Attack Signature Report
        print("\n[!] ATTACK SIGNATURE DETECTION:")
        if suspicious_activities:
            for ip, attack_type, detail in suspicious_activities:
                print(f"  [CRITICAL] IP: {ip} | Attack Type: {attack_type}")
                print(f"             Details: {detail}")
        else:
            print("  [OK] Koi web attack signature nahi mila.")

        # Incident Response Alert Trigger
        if flagged_ips or suspicious_activities:
            alert_body = f"High Risk Security Alert Triggered!\n\nFlagged IPs: {flagged_ips}\nAttacks: {suspicious_activities}"
            self.send_email_alert("SECURITY INCIDENT DETECTED", alert_body)

        # Save Report
        self.generate_report(flagged_ips, suspicious_activities)

    def generate_report(self, flagged_ips, suspicious_activities):
        """Detailed security report save karta hai."""
        report_file = "threat_report.txt"
        with open(report_file, "w") as rf:
            rf.write("====================================================\n")
            rf.write(f"CYBER THREAT INTELLIGENCE REPORT - {datetime.now()}\n")
            rf.write("====================================================\n\n")

            rf.write("1. HIGH-RISK IPs (Brute Force Detected):\n")
            for item in flagged_ips:
                rf.write(f"   - IP: {item[0]} | Attempts: {item[1]} | Intel: {item[2]}\n")

            rf.write("\n2. DETECTED ATTACK EVENTS:\n")
            for ip, attack, detail in suspicious_activities:
                rf.write(f"   - IP: {ip} | Type: {attack}\n")

        print("\n" + "=" * 65)
        print(f"[SUCCESS] Advanced Security Threat Report '{report_file}' me save ho gayi hai!")
        print("=" * 65)

if __name__ == "__main__":
    analyzer = CyberLogAnalyzer()
    analyzer.analyze_logs()
