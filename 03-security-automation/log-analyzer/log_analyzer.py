import re
import sys
from collections import defaultdict
from datetime import datetime

FAILED_PATTERN = r"LOGIN_FAILED user=(\w+) ip=([\d\.]+)"
SUCCESS_PATTERN = r"LOGIN_SUCCESS user=(\w+) ip=([\d\.]+)"

failed_attempts = defaultdict(int)
ip_targets = defaultdict(set)

BRUTE_FORCE_THRESHOLD = 3

def analyze_logs(log_file):

    try:
        with open(log_file, "r") as file:
            for line in file:

                failed_match = re.search(FAILED_PATTERN, line)

                if failed_match:

                    user = failed_match.group(1)
                    ip = failed_match. group(2)

                    failed_attempts[(user, ip)] += 1
                    ip_targets[ip].add(user)

    except FileNotFoundError:
        print("Log file not found.")
        sys.exit()

def load_threat_intel():

    malicious_ips = set()

    try:
        with open("threat_intel/malicious_ips.txt", "r") as file:

            for line in file:
                malicious_ips.add(line.strip())

    except FileNotFoundError:
        print("Threat intelligence file not found.")

    return malicious_ips

def generate_report(malicious_ips):

    alerts = []

    print("\nSecurity Log  Analysis Report")
    print("-" * 40)
    
    for (user, ip), count in failed_attempts.items():

        if count >= BRUTE_FORCE_THRESHOLD:
            
            reputation = "Uknown"

            if ip in malicious_ips:
                reputation = "KNOWN MALICIOUS IP"

            alert = f"""
Symbol Possible Brute Force Attack
Target User: {user}
Source IP: {ip}
Failed Attempts: {count}
Threat Intelligence: {reputation}
"""
            alerts.append(alert)
            print(alert)
    
    return alerts

    for ip, users in ip_targets.items():

        if len(users) > 2:

            alert = f"""
Symbol Suspicious Activity Detected
Source IP: {ip}
Multiple Accounts Targeted: {len(users)}
"""
            alerts.append(alert)
            print(alert)

    return alerts

def save_report(alerts):

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_file = f"reports/security_report_{timestamp}.txt"

    with open(report_file, "w") as file:

        file.write("Security Log Analysis Report\n")
        file.write("=" * 40 + "\n")

        for alert in alerts:
            file.write(alert)
            file.write("\n")

    print(f"\nReport saved to {report_file}")

def load_threat_intel():

    malicious_ips = set()

    try:
        with open("threat_intel/malicious_ips.txt", "r") as file:

            for line in file:
                malicious_ips.add(line.strip())

    except FileNotFoundError:
        print("Threat intelligence file not found.")

    return malicious_ips

def main():

    if len(sys.argv) < 2:
        print("Usage: python log_analyzer.py <logfile>")
        sys.exit()

    log_file = sys.argv[1]

    analyze_logs(log_file)

    alerts = generate_report(malicious_ips)

    if alerts:
        save_report(alerts)
    else:
        print("No suspicious activity detected.")

if __name__ == "__main__":
    main()

