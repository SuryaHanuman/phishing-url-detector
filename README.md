# Phishing URL Detection System

[![CI/CD Pipeline](https://github.com/SuryaHanuman/phishing-url-detector/actions/workflows/ci.yml/badge.svg)](https://github.com/SuryaHanuman/phishing-url-detector/actions)
[![Docker](https://img.shields.io/badge/Docker-Containerized-blue?logo=docker)](Dockerfile)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Ready-326CE5?logo=kubernetes)](k8s/)
[![Terraform](https://img.shields.io/badge/IaC-Terraform-7B42BC?logo=terraform)](terraform/)
[![Python](https://img.shields.io/badge/Python-3.11-yellow?logo=python)](requirements.txt)
[![Tests: Pytest](https://img.shields.io/badge/tests-pytest-green?logo=pytest)](tests/)

A Python-based cybersecurity and network analysis platform that analyzes URLs and identifies potentially malicious or phishing websites using multiple security analysis techniques, containerized with Docker, automated via CI/CD, and orchestrated with Kubernetes.

---

## Overview

Phishing attacks often use deceptive URLs to trick users into visiting malicious websites or revealing sensitive information.

This project analyzes a given URL using multiple layers of analysis and calculates an overall risk score. The system examines the URL, DNS information, HTTP behavior, SSL/TLS certificate details, WHOIS information, and HTML content.

---

## Features

- URL structure and lexical analysis
- IP address detection
- Suspicious keyword detection
- Brand impersonation detection
- Suspicious TLD detection
- URL shortening detection
- URL entropy analysis (Shannon entropy)
- DNS analysis (A, AAAA, MX, NS, TXT, and CNAME records)
- HTTP response and redirect analysis
- Security header analysis
- SSL/TLS certificate analysis
- TLS version analysis
- WHOIS domain information analysis
- Domain age analysis
- HTML content analysis
- Login form detection
- Password field detection
- External form action detection
- External iframe detection
- JavaScript redirect detection
- Meta refresh detection
- Multi-factor risk scoring engine

---

## Project Architecture

The system consists of several specialized analyzers:

```text
                         URL
                          |
                          v
                  +---------------+
                  |  URL Analyzer |
                  +---------------+
                          |
          +---------------+---------------+
          |               |               |
          v               v               v
    DNS Analyzer    HTTP Analyzer    SSL Analyzer
          |               |               |
          |               |               |
          +---------------+---------------+
                          |
                          v
                  WHOIS Analyzer
                          |
                          v
                   HTML Analyzer
                          |
                          v
                    Risk Engine
                          |
                          v
                  Risk Assessment
```

---

## DevOps & Cloud Infrastructure

### 1. Containerization (Docker)
- Production-grade multi-stage `Dockerfile` built on `python:3.11-slim`.
- Runs as a non-privileged `appuser` (UID 10001) for least-privilege security.
- Healthcheck probe ensuring core modules import cleanly.

```bash
# Build the Docker image
docker build -t suryahanuman/phishing-url-detector:latest .

# Run container interactively
docker run -it --rm suryahanuman/phishing-url-detector:latest
```

### 2. Automated CI/CD Pipeline (GitHub Actions)
Located at `.github/workflows/ci.yml`, the pipeline triggers on all pushes and pull requests:
- **Linting:** Enforces Python syntax and import standards with `flake8`.
- **Unit Testing:** Executes automated tests via `pytest` with coverage tracking.
- **Docker Build Smoke Test:** Verifies that the container image builds without errors.

### 3. Kubernetes Orchestration (`k8s/`)
Production-ready manifests for container deployment:
- `k8s/deployment.yaml`: Configured with RollingUpdate strategy (`maxSurge: 1`, `maxUnavailable: 0`), CPU/memory requests and limits, and container liveness probes.
- `k8s/service.yaml`: ClusterIP service routing traffic within the cluster.

```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```

### 4. Infrastructure as Code (`terraform/`)
Modular **Terraform** configuration provisioning AWS Free-Tier infrastructure (`t2.micro` EC2 + Security Group) with automated Docker installation via cloud-init.

```bash
cd terraform
terraform init
terraform validate
terraform plan
```

---

## Project Structure

```text
phishing-url-detector/
├── .github/
│   └── workflows/
│       └── ci.yml               # Automated CI/CD Pipeline (GitHub Actions)
├── k8s/
│   ├── deployment.yaml         # Kubernetes Deployment with Health Probes
│   └── service.yaml            # Kubernetes ClusterIP Service
├── terraform/
│   └── main.tf                 # AWS Free-Tier EC2 & Security Group IaC
├── tests/
│   ├── __init__.py
│   └── test_url_analyzer.py    # Pytest Unit Tests for URLAnalyzer
├── scripts/
│   ├── setup.sh                # Linux environment bootstrap script
│   └── run.sh                  # Execution & Docker helper script
├── main.py                     # Program entry point & CLI scanner
├── url_analyzer.py             # URL lexical & structural analysis
├── dns_analyzer.py             # DNS record retrieval & validation
├── http_analyzer.py            # HTTP request & redirect tracing
├── ssl_analyzer.py             # SSL/TLS certificate inspection
├── whois_analyzer.py           # WHOIS domain registration analysis
├── html_analyzer.py            # HTML DOM parsing & form detection
├── risk_engine.py              # Multi-factor risk scoring engine
├── Dockerfile                  # Lightweight non-root container image
├── .dockerignore               # Container build exclusions
├── requirements.txt            # Production runtime requirements
├── requirements-dev.txt        # Testing & linting requirements
└── README.md                   # System documentation
```

---

## Installation & Local Setup

### Quick Setup with Bash Script

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### Manual Installation

Clone the repository:

```bash
git clone https://github.com/SuryaHanuman/phishing-url-detector.git
cd phishing-url-detector
```

Install the required dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

Run the unit test suite:

```bash
pytest tests/ -v
```

---

## Usage

Run the application:

```bash
python main.py
```

Enter a URL when prompted. The system performs multiple analyses and generates an overall risk score and severity level.

---

## Risk Levels

| Score | Risk Level |
|------:|------------|
| 0–9   | SAFE       |
| 10–24 | LOW        |
| 25–49 | MEDIUM     |
| 50–74 | HIGH       |
| 75–100 | CRITICAL  |

---

## Analysis Modules

### URL Analyzer
Examines URL structure:
- IP addresses
- Suspicious keywords
- Suspicious TLDs
- Excessive subdomains
- Multiple hyphens
- URL encoding
- High-entropy domains (Shannon entropy)
- URL shorteners
- Brand impersonation

### DNS Analyzer
Performs DNS lookups via `dnspython`:
- IPv4 (A) & IPv6 (AAAA) records
- MX records
- NS records
- TXT records
- CNAME records

### HTTP Analyzer
Examines HTTP behavior:
- HTTP status codes
- Redirect chains & cross-domain hops
- Final destination
- Security headers

### SSL Analyzer
Examines SSL/TLS certificates:
- TLS version
- Certificate validity & expiration
- Hostname matching
- Cipher suites

### WHOIS Analyzer
Examines domain registration:
- Registrar & creation/expiration dates
- Domain age
- Recently registered domain detection

### HTML Analyzer
Analyzes HTML content via `BeautifulSoup`:
- Login forms & password fields
- External form actions
- External iframes
- JavaScript & Meta refresh redirects

### Risk Engine
Combines findings from all analyzers and calculates an overall risk score from **0 to 100**.

---

## Disclaimer

This project is intended for educational, research, and cybersecurity learning purposes.
The detection results are heuristic-based and should not be considered a definitive determination that a website is malicious or safe. Only analyze URLs and websites that you are authorized to investigate.

---

## Author

**Surya Hanuman**  
GitHub: [SuryaHanuman](https://github.com/SuryaHanuman)
