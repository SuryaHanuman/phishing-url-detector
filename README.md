# Phishing URL Detection System

A Python-based cybersecurity project that analyzes URLs and identifies potentially malicious or phishing websites using multiple security analysis techniques.

## Overview

Phishing attacks often use deceptive URLs to trick users into visiting malicious websites or revealing sensitive information.

This project analyzes a given URL using multiple layers of analysis and calculates an overall risk score. The system examines the URL, DNS information, HTTP behavior, SSL/TLS certificate details, WHOIS information, and HTML content.

## Features

- URL structure and lexical analysis
- IP address detection
- Suspicious keyword detection
- Brand impersonation detection
- Suspicious TLD detection
- URL shortening detection
- URL entropy analysis
- DNS analysis
- A, AAAA, MX, NS, TXT and CNAME record analysis
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
- Risk scoring and severity classification

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

## Project Structure

```text
phishing-url-detector/
│
├── main.py
├── url_analyzer.py
├── dns_analyzer.py
├── http_analyzer.py
├── ssl_analyzer.py
├── whois_analyzer.py
├── html_analyzer.py
├── risk_engine.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Technologies Used

- Python
- DNS analysis
- HTTP/HTTPS analysis
- SSL/TLS certificate analysis
- WHOIS analysis
- HTML parsing
- BeautifulSoup
- Regular expressions
- Socket programming

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/phishing-url-detector.git
cd phishing-url-detector
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the application:

```bash
python main.py
```

Enter a URL when prompted.

The system performs multiple analyses and generates an overall risk score and severity level.

## Risk Levels

| Score | Risk Level |
|------:|------------|
| 0–9   | SAFE       |
| 10–24 | LOW        |
| 25–49 | MEDIUM     |
| 50–74 | HIGH       |
| 75–100 | CRITICAL  |

## Analysis Modules

### URL Analyzer

Examines the structure of the URL and looks for characteristics commonly associated with phishing URLs, including:

- IP addresses
- Suspicious keywords
- Suspicious TLDs
- Excessive subdomains
- Multiple hyphens
- URL encoding
- High-entropy domains
- URL shorteners
- Brand impersonation

### DNS Analyzer

Performs DNS analysis and retrieves information such as:

- IPv4 addresses
- IPv6 addresses
- MX records
- NS records
- TXT records
- CNAME records

### HTTP Analyzer

Examines HTTP/HTTPS behavior including:

- HTTP status codes
- Redirect chains
- Cross-domain redirects
- Final destination
- Security headers
- HTML content

### SSL Analyzer

For HTTPS URLs, the system examines:

- TLS version
- Certificate validity
- Certificate expiration
- Hostname matching
- Cipher information
- Certificate expiration period

### WHOIS Analyzer

Examines domain registration information such as:

- Registrar
- Creation date
- Expiration date
- Domain age
- Recently registered domains

### HTML Analyzer

Analyzes downloaded HTML content for potentially suspicious characteristics such as:

- Login forms
- Password fields
- External form actions
- External iframes
- JavaScript redirects
- Meta refresh redirects
- Phishing-related keywords

### Risk Engine

The Risk Engine combines the results from all analyzers and calculates an overall risk score from **0 to 100**.

The final result includes:

- Risk score
- Risk level
- Number of findings
- Detailed security findings

## Disclaimer

This project is intended for educational, research, and cybersecurity learning purposes.

The detection results are heuristic-based and should not be considered a definitive determination that a website is malicious or safe.

Only analyze URLs and websites that you are authorized to investigate.

## Author

**Surya Hanuman**
