
# Cyber Threat Intelligence & Log Analyzer

An automated Python tool designed to parse server logs, detect malicious security threats like Brute-Force attacks and SQL Injections, query Threat Intelligence APIs, and generate automated security reports.

## Features
- **Log Parsing:** Extracts IPs, timestamps, and login attempts using Regular Expressions (Regex).
- **Brute-Force Detection:** Flags IP addresses exceeding failed login thresholds.
- **Attack Signature Detection:** Identifies web attack patterns like SQL Injection.
- **Threat Intel Readiness:** Integrated VirusTotal API query structure for real-time IP reputation analysis.
- **Incident Response:** Automated generation of `threat_report.txt` and readiness for email alerting.

## Tech Stack
- Python 3.8+
- Built-in Modules: `re`, `os`, `json`, `urllib`, `datetime`, `smtplib`

## How to Run
1. Clone the repository or download `vanshhpythonproject1.py`.
2. Run the script using Python IDLE or terminal:
   ```bash
   python vanshhpythonproject1.py
