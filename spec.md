Login Analyser Specifications

-We need to count only "failed passwords" lines

-Ignore authentication failures, that is PAM's side of saying the passwords didn't match, which would be duplicating items I am already counting for.

-Make a allowlist of trusted IP's that will still get reported with a allowlisted label, but will have a label on it showing that it is a trusted IP.

-Count repeated passwords for their real value, instead of just 1
-For the repeated passwords, the analyzer only works for this specific log, because the index of repeated passwords is always 7, its not flexible with other logs yet.