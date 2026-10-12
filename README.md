Parses Linux SSH auth logs to count failed and successful logins per IP and flag likely brute-force sources.

ex:
analyzer.py ran with auth.log:

IP: 24.151.103.17, Failed: 157, Success:47 
IP: 49.4.143.105, Failed: 120, Success:0 
IP: 34.204.227.175, Failed: 43, Success:0 
IP: 201.178.81.113, Failed: 36, Success:0 
IP: 181.26.186.35, Failed: 30, Success:0 
Total: 1038 failures, 226 Successes

how to run:
version: python 3.14
command: ./python3 analyzer.py
to change files you need to edit the code to the name and path of the file you want to analyze.

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