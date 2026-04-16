import subprocess
import json

domains = []

with open("universities.txt") as f:
    domains = [d.strip() for d in f]

results = []

for domain in domains:
    print(f"Scanning {domain}")

    try:
        cmd = [
            "nmap",
            "--script",
            "ssl-enum-ciphers",
            "-p",
            "443",
            domain
        ]

        output = subprocess.check_output(cmd).decode()

        # Extract cipher lines
        lines = output.split("\n")
        cipher_lines = [line.strip() for line in lines if "TLS_" in line]

        supports_ecdhe = False
        supports_rsa = False

        for line in cipher_lines:
            if "ECDHE" in line:
                supports_ecdhe = True
            if "TLS_RSA" in line:
                supports_rsa = True

        # New classification logic
        fully_secure = supports_ecdhe and not supports_rsa
        vulnerable_hndl = supports_rsa

        results.append({
            "domain": domain,
            "supports_forward_secrecy": supports_ecdhe,
            "supports_rsa": supports_rsa,
            "fully_secure": fully_secure,
            "vulnerable_to_hndl": vulnerable_hndl
        })

    except Exception as e:
        results.append({
            "domain": domain,
            "error": str(e)
        })

with open("results.json", "w") as f:
    json.dump(results, f, indent=4)

print("Scan complete. Results saved to results.json")