Login Analyser Specifications

-The goal is to count which ip addresses 
-Ignore authentication failures, that is PAM's side of saying the passwords didn't match, which would be duplicating items I am already counting for.

-Make a allowlist of trusted IP's that will still get reported with a allowlisted label, but will have a label on it showing that it is a trusted IP.

-Count repeated passwords for their real value, instead of just 1
-Using python regex, the re.search may need to be changed based on the words in front of and behind the repeated number and IP, but will be flexible with most logs.

