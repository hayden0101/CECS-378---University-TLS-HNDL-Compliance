import json
import csv

with open("results.json") as f:
    data = json.load(f)

# Filter out failed scans
valid_data = [d for d in data if "error" not in d]

total = len(valid_data)

fs_count = sum(1 for d in valid_data if d["supports_forward_secrecy"])
rsa_count = sum(1 for d in valid_data if d["supports_rsa"])
secure_count = sum(1 for d in valid_data if d["fully_secure"])
vulnerable_count = sum(1 for d in valid_data if d["vulnerable_to_hndl"])

print("===== TLS ANALYSIS RESULTS =====")
print(f"Total Sites: {total}")

print(f"\nForward Secrecy Supported: {fs_count} ({(fs_count/total)*100:.2f}%)")
print(f"Supports RSA (HNDL Risk): {rsa_count} ({(rsa_count/total)*100:.2f}%)")
print(f"Fully Secure (No RSA): {secure_count} ({(secure_count/total)*100:.2f}%)")
print(f"Vulnerable to HNDL: {vulnerable_count} ({(vulnerable_count/total)*100:.2f}%)")

# Save CSV for graphs
with open("results.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "domain",
        "supports_forward_secrecy",
        "supports_rsa",
        "fully_secure",
        "vulnerable_to_hndl"
    ])

    for d in valid_data:
        writer.writerow([
            d["domain"],
            d["supports_forward_secrecy"],
            d["supports_rsa"],
            d["fully_secure"],
            d["vulnerable_to_hndl"]
        ])

print("\nCSV file saved as results.csv")