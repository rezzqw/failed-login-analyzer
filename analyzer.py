import re
IP = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
REPEATED = re.compile(r"^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ sshd\[\d+\]: message repeated (\d+) times: \[ Failed password for .+ from " + IP + r" port \d+ ssh2\]$")
ACCEPTED = re.compile(r"^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ sshd\[\d+\]: Accepted \S+ for \S+ from " + IP + r" port")
FAILED = re.compile(r"^\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2} \S+ sshd\[\d+\]: Failed password for .+ from " + IP + r" port \d+ ssh2$")
ip_addresses_failures = {}
ip_addresses_successes = {}
with open("samples/auth.log", "r") as auth_log:
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
        
#Rank the ips with most attempts
ranked_ip_fails = sorted(ip_addresses_failures.items(), key=lambda pair: pair[1], reverse=True)
top_five = ranked_ip_fails[:5]

for ip, failed_attempts in top_five:
    print(f"IP: {ip}, Failed: {failed_attempts}, Success:{ip_addresses_successes.get(ip, 0)} ")


print(f"Total: {sum(ip_addresses_failures.values())} failures, {sum(ip_addresses_successes.values())} Successes")