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
    # Force TLS 1.2 + RSA cipher
    output = run_cmd(f"echo | openssl s_client -connect {domain}:443 -tls1_2 -cipher AES256-SHA")
    return "Cipher    : AES256-SHA" in output or "TLS_RSA" in output

def check_ecdhe(domain):
    output = run_cmd(f"echo | openssl s_client -connect {domain}:443 -tls1_2 -cipher ECDHE")
    return "ECDHE" in output

# --- MAIN SCAN ---

def scan_domain(domain):
    tls13 = check_tls13(domain)
    tls12 = check_tls12(domain)
    rsa = check_rsa_kx(domain)
    ecdhe = check_ecdhe(domain)

    # Classification logic
    vulnerable_hndl = rsa
    fully_secure = ecdhe and not rsa

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
