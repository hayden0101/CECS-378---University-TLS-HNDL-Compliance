import json
import matplotlib.pyplot as plt

with open("results.json") as f:
    data = json.load(f)

valid_data = [d for d in data if "error" not in d]

# --- Counts ---
tls13 = sum(1 for d in valid_data if d.get("supports_tls13"))
tls12 = sum(1 for d in valid_data if d.get("supports_tls12"))
ecdhe = sum(1 for d in valid_data if d.get("supports_ecdhe"))
rsa = sum(1 for d in valid_data if d.get("supports_rsa_kx"))
secure = sum(1 for d in valid_data if d.get("fully_secure"))

# --- Graph 1: TLS Versions ---
labels1 = ["TLS 1.3", "TLS 1.2"]
values1 = [tls13, tls12]

plt.figure()
plt.bar(labels1, values1)
plt.title("TLS Version Support Among University Servers")
plt.xlabel("TLS Version")
plt.ylabel("Number of Servers")
plt.show()

# --- Graph 2: Security Properties ---
labels2 = ["Forward Secrecy (ECDHE)", "RSA (HNDL Risk)", "Fully Secure"]
values2 = [ecdhe, rsa, secure]

plt.figure()
plt.bar(labels2, values2)
plt.title("TLS Security Properties of University Servers")
plt.xlabel("Category")
plt.ylabel("Number of Servers")
plt.show()
