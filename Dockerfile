FROM python:3.11

Run apt-get update && apt-get install -y \
    nmap \
    openssl

WORKDIR /app

COPY . .

CMD ["python", "scan.py"]