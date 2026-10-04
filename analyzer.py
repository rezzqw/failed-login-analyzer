count = 0
with open("auth.log", "r") as auth_log:
    for entry in auth_log:
        if "Failed password" in entry:
            if "repeated" in entry:
                entry_split = entry.split()
                repeat_num = int(entry_split[7]) #This 7 only works right now for this log file, need to implement something different
                count += repeat_num
            else:
                count += 1
               




print(f"Total: {count}")