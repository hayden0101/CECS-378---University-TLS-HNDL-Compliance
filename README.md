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

## Research Goal

This project aims to:
- Measure how many university servers lack forward secrecy
- Evaluate exposure to retrospective decryption (HNDL)
- Provide data-driven insights for improving TLS security

---

## Future Improvements

- Scale to 250+ university domains
- Improve cipher suite parsing accuracy
- Replace nmap with faster scanners (e.g., zgrab2)
- Add lab demonstration of TLS decryption
