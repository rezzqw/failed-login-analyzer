import re
import argparse

parser = argparse.ArgumentParser(description="Parses Linux SSH auth logs to count failed and successful logins per IP and flag likely brute-force sources")
parser.add_argument("file", help="path to the Linux SSH auth log file")
parser.add_argument("--threshold", type=int, default=10, help="threshold for failed attempts to start counting (default: 10)")
args = parser.parse_args()

#Make sure threshold is 1 or larger
if args.threshold < 1:
    parser.error(f"Error: Threshold: {args.threshold}, threshold must be at least 1")

IP = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
REPEATED = re.compile(r"^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ sshd\[\d+\]: message repeated (\d+) times: \[ Failed password for .+ from " + IP + r" port \d+ ssh2\]$")
ACCEPTED = re.compile(r"^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ sshd\[\d+\]: Accepted \S+ for \S+ from " + IP + r" port")
FAILED = re.compile(r"^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ sshd\[\d+\]: Failed password for .+ from " + IP + r" port \d+ ssh2$")
ip_addresses_failures = {}
ip_addresses_successes = {}

try: 
    with open(args.file, "r") as auth_log:
        for entry in auth_log:
            repeat_match = REPEATED.match(entry)
            if repeat_match is not None:
                attempts = int(repeat_match.group(1))
                ip_f = repeat_match.group(2)
                ip_addresses_failures[ip_f] = ip_addresses_failures.get(ip_f, 0) + attempts
                continue

            ip_failed = FAILED.match(entry)
            if ip_failed is not None:
                attempts = 1
                ip_f = ip_failed.group(1)
                ip_addresses_failures[ip_f] = ip_addresses_failures.get(ip_f, 0) + attempts
                continue
            
            ip_success = ACCEPTED.match(entry)
            if ip_success is not None:
                ip_s = ip_success.group(1)
                ip_addresses_successes[ip_s] = ip_addresses_successes.get(ip_s, 0) + 1
                continue
except FileNotFoundError:
    parser.error(f"file not found: {args.file}")
except PermissionError:
    parser.eroor("Error: Permission denied to open file. Try to run with sudo")
#Rank the ips with most attempts
ranked_ip_fails = sorted(ip_addresses_failures.items(), key=lambda pair: pair[1], reverse=True)
top_five = ranked_ip_fails[:5]


for ip, failed_attempts in top_five:
    print(f"IP: {ip}, Failed: {failed_attempts}, Success:{ip_addresses_successes.get(ip, 0)} ")


print(f"Total: {sum(ip_addresses_failures.values())} failures, {sum(ip_addresses_successes.values())} Successes")