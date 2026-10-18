Parses Linux SSH auth logs to count failed and successful logins per IP and flag likely brute-force sources.

ex:
analyzer.py ran with auth.log and a threshold of 10:



how to run:
version: python 3.14
command: ./python3 analyzer.py <auth log file path>

how it works:
Failed password lines count as 1
message repeated N times lines count as N
PAM authentication failure lines are skipped as duplicates
Successful logins are tracked separately, by password or key

limitations:
Only standard syslog timestamps, not ISO 8601 formats from newer Ubuntu
Failed public key attempts aren’t logged by sshd by default, so key spraying is invisible
Invalid user probes and max-auth disconnects aren’t counted yet
Only IPv4
Total counts, not attempts per time window