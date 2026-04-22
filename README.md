# TLS Forward Secrecy Study

This project analyzes TLS configurations of U.S. university websites to determine the prevalence of forward secrecy and identify potential risk under the Harvest-Now-Decrypt-Later (HNDL) threat model.

---

## Project Structure

```
tls-university-study/
│
├── Dockerfile
├── scan.py
├── universities.txt
├── results.json        # Generated after scanning
├── analysis.py
├── graph.py
└── tls_graph.png       # Generated after graphing
├   |── phase2/
│   ├   |── server.crt
│   ├   |── server.key
│   ├   |── phase2_rsa.pcap
│   └   |── phase2_ecdhe.pcap
```

---

## Running the TLS Scanner (Docker)

### 1. Start Docker Desktop
Make sure Docker Desktop is running and the engine is active.

---

### 2. Build the Docker Image

In your project folder, run:

```
docker build -t tls-scanner .
```

---

### 3. Run the Scanner

```
docker run --rm -v ${PWD}:/app tls-scanner
```

This will:
- Read domains from `universities.txt`
- Scan TLS configurations
- Save results to `results.json`

---

### Note
- Scanning may take time (especially with many domains)

---

## Running the TLS Scan (What It Does)

The scanner:
- Connects to each domain on port 443
- Extracts TLS cipher suite information
- Detects:
  - Forward secrecy (ECDHE)
  - RSA key exchange (no forward secrecy)

Output example (`results.json`):

```
[
  {
    "domain": "example.edu",
    "forward_secrecy": true,
    "rsa_key_exchange": false
  }
]
```

---

## Running Analysis

Run the analysis script:

```
python analysis.py
```

This will output:

- Total number of sites scanned
- Number supporting forward secrecy
- Number supporting RSA key exchange
- Percentage of vulnerable sites

---

## Generating Graphs

### 1. Install required library (if needed)

```
pip install matplotlib
```

---

### 2. Run graph script

```
python graph.py
```

This will:
- Display a bar chart
- Save it as `tls_graph.png`

---

## Workflow Summary

```
1. Update universities.txt
2. Run Docker scan
3. Generate results.json
4. Run analysis.py
5. Run graph.py
```
---

### Phase 2
- Ubuntu (WSL on Windows, or native Linux)
- OpenSSL
- tcpdump
- curl (Linux build)
- Wireshark (Windows)

---

## Phase 2: Controlled HNDL Experiment

Phase 2 is run locally in **Ubuntu (WSL)**. All commands below are run in Ubuntu unless noted.

### Step 1 — Generate Certificate and Key

```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
  -days 365 -nodes -subj "/CN=localhost"
```

---

### Step 2 — Start Server A (RSA / Non-Forward-Secret)

```bash
openssl s_server -accept 4433 \
  -cert server.crt -key server.key \
  -cipher "AES256-SHA" \
  -no_tls1_3 \
  -WWW
```

Verify cipher negotiation in a second terminal:

```bash
openssl s_client -connect 127.0.0.1:4433 | grep "Cipher is"
```

Expected output:
```
New, TLSv1.2, Cipher is AES256-SHA
```
No `ECDHE` prefix = RSA key exchange = **no forward secrecy**.

---

### Step 3 — Start Server B (ECDHE / Forward-Secret)

```bash
openssl s_server -accept 4434 \
  -cert server.crt -key server.key \
  -cipher "ECDHE-RSA-AES256-SHA" \
  -no_tls1_3 \
  -WWW
```

Verify cipher negotiation:

```bash
openssl s_client -connect 127.0.0.1:4434
```

Expected output:
```
Cipher is ECDHE-RSA-AES256-SHA
Server Temp Key: X25519, 253 bits
```

`Server Temp Key` confirms an ephemeral key is in use = **forward secrecy active**.

---

### Step 4 — Capture Traffic with tcpdump

> Wireshark on Windows cannot capture WSL loopback traffic directly. Use `tcpdump` inside WSL to export a `.pcap` file.

**Capture Server A traffic:**
```bash
sudo tcpdump -i lo port 4433 -w phase2_rsa.pcap
```

**In a separate terminal, generate traffic:**
```bash
curl https://127.0.0.1:4433 -k -v --tls-max 1.2 --ciphers "AES256-SHA"
```

Stop tcpdump with `Ctrl+C`, then open in Wireshark:
```bash
explorer.exe phase2_rsa.pcap
```

Repeat for Server B:
```bash
sudo tcpdump -i lo port 4434 -w phase2_ecdhe.pcap
curl https://127.0.0.1:4434 -k -v --tls-max 1.2 --ciphers "ECDHE-RSA-AES256-SHA"
explorer.exe phase2_ecdhe.pcap
```

---

### Step 5 — Attempt Decryption in Wireshark

1. Go to **Edit -> Preferences -> Protocols -> TLS**
2. Under **RSA Keys List**, click **+** and add:

| Field | Value |
|---|---|
| IP Address | 127.0.0.1 |
| Port | 4433 (or 4434) |
| Protocol | http |
| Key File | path to `server.key` |

---

## Results

| Server | Configuration | Decryptable with Private Key? |
|---|---|---|
| Server A | TLS 1.2 / RSA (AES256-SHA) | Yes - GET / HTTP/1.1 visible in plaintext |
| Server B | TLS 1.2 / ECDHE (ECDHE-RSA-AES256-SHA) | No - Encrypted Alert; session unrecoverable |

---

## Research Goal

This project aims to:
- Measure how many university servers lack forward secrecy
- Evaluate exposure to retrospective decryption (HNDL)
- Provide data-driven insights for improving TLS security

