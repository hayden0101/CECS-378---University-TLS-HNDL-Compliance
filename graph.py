import json
import matplotlib.pyplot as plt

with open("results.json") as f:
    data = json.load(f)

valid_data = [d for d in data if "error" not in d]

labels = ["Forward Secrecy", "RSA Support", "Fully Secure"]

fs = sum(1 for d in valid_data if d["supports_forward_secrecy"])
rsa = sum(1 for d in valid_data if d["supports_rsa"])
secure = sum(1 for d in valid_data if d["fully_secure"])

values = [fs, rsa, secure]

plt.bar(labels, values)
plt.title("TLS Security Properties of University Servers")
plt.xlabel("Category")
plt.ylabel("Number of Servers")

plt.show()