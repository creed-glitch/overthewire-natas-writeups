import re
from collections import defaultdict

FAILED_LOGIN_PATTERN = r"LOGIN_FAILED user=(\w+) ip=([\d\.]+)"

failed_attempts = defaultdict(int)

log_file = "sample_logs/auth.log"

with open(log_file, "r") as file:
    for line in file:
        match = re.search(Failed_LOGIN_PATTERN, line)

        if match:
            user = match.group(1)
            ip = match.group(2)

            failed_attempts[(user, ip)] += 1

# detection logic
THRESHOLD = 3

print("\nSecurity Log Analysis Report\n")

for (user, ip), count in failed_attempts.items():
    if count >= THRESHOLD:
        print(" Possible Brute Force Detected")
        print(f"Target User: {user}")
        print(f"Source IP: {ip}")
        print(f"Failed Attempts: {count}\n")

