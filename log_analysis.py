"""
Linux Log Analysis Script
Author: Ayush Yadav

Description:
Scans Linux authentication logs (lines 200–500) to detect suspicious login activity and exports results to a CSV file.
"""
import csv

# Read Log File
 
with open("Linux_2k.log", "r", encoding="utf-8") as file:
    logs = file.readlines()

# Extract specific range of log entries
subset_logs = logs[199:500] 

# Delect Suspicious Activity
suspicious_entries = []
for line in subset_logs:
   if "Failed password" in line:
     suspicious_entries.append(("Failed Login", line.strip()))
   elif "authentication failure" in line:
     suspicious_entries.append(("Auth Failure", line.strip()))
   elif "user unknown" in line or "invalid user" in line:

    suspicious_entries.append(("Unknown User", line.strip()))

#Print Results
print("=== Suspicious Log Entries (Lines 200–500) ===")
for entry_type, entry in suspicious_entries:
  print(f"[{entry_type}] {entry}")

print(f"\nTotal  suspicious entries found:{len(suspicious_entries)}")

# Export to CSV
with open("suspicious_logs.csv", "w", newline="") as csvfile:

    writer = csv.writer(csvfile)
    writer.writerow(["Type", "Log Entry"])
    writer.writerows(suspicious_entries)
print("Results saved to suspicious_logs.csv")