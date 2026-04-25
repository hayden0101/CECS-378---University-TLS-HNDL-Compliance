import json
import csv

with open("results.json") as f:
    data = json.load(f)

# Filter out failed scans
valid_data = [d for d in data if "error" not in d]

total = len(valid_data)

# Updated fields
fs_count = sum(1 for d in valid_data if d.get("supports_ecdhe"))
rsa_count = sum(1 for d in valid_data if d.get("supports_rsa_kx"))
secure_count = sum(1 for d in valid_data if d.get("fully_secure"))
vulnerable_count = sum(1 for d in valid_data if d.get("vulnerable_to_hndl"))

# NEW: TLS version stats
tls13_count = sum(1 for d in valid_data if d.get("supports_tls13"))
tls12_count = sum(1 for d in valid_data if d.get("supports_tls12"))

print("===== TLS ANALYSIS RESULTS =====")
print(f"Total Sites: {total}")

print(f"\nTLS 1.3 Supported: {tls13_count} ({(tls13_count/total)*100:.2f}%)")
print(f"TLS 1.2 Supported: {tls12_count} ({(tls12_count/total)*100:.2f}%)")

print(f"\nForward Secrecy (ECDHE): {fs_count} ({(fs_count/total)*100:.2f}%)")
print(f"Supports RSA (HNDL Risk): {rsa_count} ({(rsa_count/total)*100:.2f}%)")

print(f"\nFully Secure (No RSA): {secure_count} ({(secure_count/total)*100:.2f}%)")
print(f"Vulnerable to HNDL: {vulnerable_count} ({(vulnerable_count/total)*100:.2f}%)")

# Save CSV for graphs
with open("results.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "domain",
        "supports_tls13",
        "supports_tls12",
        "supports_ecdhe",
        "supports_rsa_kx",
        "fully_secure",
        "vulnerable_to_hndl"
    ])

    for d in valid_data:
        writer.writerow([
            d.get("domain"),
            d.get("supports_tls13"),
            d.get("supports_tls12"),
            d.get("supports_ecdhe"),
            d.get("supports_rsa_kx"),
            d.get("fully_secure"),
            d.get("vulnerable_to_hndl")
        ])

print("\nCSV file saved as results.csv")
