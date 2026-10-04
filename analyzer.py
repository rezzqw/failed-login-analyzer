count = 0
with open("LoginAna/auth.log", "r") as auth_log:
    for entry in auth_log:
        if "Failed password" in entry:
            count += 1

print(f"Total: {count}")