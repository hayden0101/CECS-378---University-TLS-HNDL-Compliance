import subprocess
import json

def run_cmd(cmd):
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout + result.stderr
    except:
        return ""

# --- TLS VERSION CHECKS ---

def check_tls13(domain):
    output = run_cmd(f"echo | openssl s_client -connect {domain}:443 -tls1_3")
    return "Protocol  : TLSv1.3" in output

def check_tls12(domain):
    output = run_cmd(f"echo | openssl s_client -connect {domain}:443 -tls1_2")
    return "Protocol  : TLSv1.2" in output

# --- CIPHER TYPE CHECKS ---

def check_rsa_kx(domain):
    # Offer only known RSA key exchange ciphers (no ECDHE prefix = RSA Kx by definition)
    output = run_cmd(
        f"echo | openssl s_client -connect {domain}:443 -tls1_2 "
        f"-cipher 'AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256' 2>&1"
    )
    # Handshake succeeded with an RSA-only cipher and ECDHE was not involved
    return (
        "Cipher    :" in output and
        "ECDHE" not in output and
        any(c in output for c in ["AES128-SHA", "AES256-SHA", "AES128-SHA256", "AES256-SHA256"])
    )

def check_ecdhe(domain):
    # Offer only ECDHE ciphers on TLS 1.2
    output = run_cmd(
        f"echo | openssl s_client -connect {domain}:443 -tls1_2 "
        f"-cipher 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA' 2>&1"
    )
    return "ECDHE" in output and "Cipher    :" in output

# --- MAIN SCAN ---

def scan_domain(domain):
    tls13 = check_tls13(domain)
    tls12 = check_tls12(domain)

    # Only probe cipher suites if TLS 1.2 is supported
    # TLS 1.3-only servers are unconditionally forward secret by protocol design
    if tls12:
        rsa = check_rsa_kx(domain)
        ecdhe = check_ecdhe(domain)
    else:
        rsa = False
        ecdhe = tls13  # TLS 1.3 guarantees ECDHE equivalent

    vulnerable_hndl = rsa
    fully_secure = (tls13 and not tls12) or (ecdhe and not rsa)

    return {
        "domain": domain,
        "supports_tls13": tls13,
        "supports_tls12": tls12,
        "supports_rsa_kx": rsa,
        "supports_ecdhe": ecdhe,
        "vulnerable_to_hndl": vulnerable_hndl,
        "fully_secure": fully_secure
    }

# --- DRIVER ---

def main():
    results = []

    with open("universities.txt") as f:
        domains = [line.strip() for line in f if line.strip()]

    for domain in domains:
        print(f"Scanning {domain}...")
        results.append(scan_domain(domain))

    with open("results.json", "w") as f:
        json.dump(results, f, indent=4)

    print("Scan complete. Results saved to results.json")

if __name__ == "__main__":
    main()
