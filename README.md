```
    ██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
    ██║  ██║█████╗  ██║  ██║███████╗█████╗  ██║
    ██║  ██║██╔══╝  ██║  ██║╚════██║██╔══╝  ██║
    ██████╔╝███████╗██████╔╝███████║███████╗╚██████╗
    ╚═════╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝
```

# DEDSEC — Web Reconnaissance Framework

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Author](https://img.shields.io/badge/Author-Sohaim-red?style=flat-square)

DEDSEC is an advanced, modular web reconnaissance framework for the recon phase of authorized penetration testing. Scan targets for technology fingerprints, DNS records, open ports, SSL issues, security misconfigurations, and more — all from a single CLI.

---

## Features

| # | Module | Description |
|---|--------|-------------|
| 1 | 🛡️ WAF Detection | Detects 12+ WAFs with confidence scoring and trigger payloads |
| 2 | 🌐 Tech Fingerprinting | Languages, servers, CMS, JS frameworks, CDN, analytics |
| 3 | 🔍 DNS Recon | A/AAAA/MX/NS/TXT/CNAME/SOA records + zone transfer attempt |
| 4 | 🌍 IP & GeoLocation | IP resolve + country, city, ISP, ASN via ip-api.com |
| 5 | 🔒 SSL/TLS Analysis | Cert expiry, SANs, protocol version, serial number |
| 6 | 📋 Header Audit | 12 security headers check + information disclosure detection |
| 7 | 🚪 Open Redirect | Tests 15 common redirect parameters for open redirect |
| 8 | 🤖 Robots & Sitemap | Parses robots.txt + probes common sitemap URLs |
| 9 | 🍪 Cookie Audit | HttpOnly, Secure, SameSite flag checks with risk explanations |
| 10 | 📡 Port Scan | Top 25 ports via concurrent scanning with service names |
| 11 | 🕵️ WHOIS Lookup | Registrar, dates, nameservers, org, country |
| 12 | 🌐 Subdomain Enum | Passive via crt.sh Certificate Transparency (up to 50) |
| 13 | 📜 JS & Endpoint Extraction | JS files, API endpoints, email addresses from page source |

---

## Installation

```bash
git clone https://github.com/muhammadsohaimmuqtada/dedsec.git
cd dedsec
pip install -e .
```

Or install dependencies manually:

```bash
pip install -r requirements.txt
```

---

## Usage

**Scan all modules:**
```bash
dedsec https://example.com
```

**Run specific modules:**
```bash
dedsec https://example.com --modules waf ssl headers dns
```

**JSON output:**
```bash
dedsec https://example.com --json
```

**Save report to file:**
```bash
dedsec https://example.com --output report.json --json
```

**Custom timeout:**
```bash
dedsec https://example.com --timeout 15
```

**Run via Python module:**
```bash
python -m dedsec https://example.com
```

### All Options

```
usage: dedsec [-h] [--modules {...}] [--timeout TIMEOUT] [--output OUTPUT] [--json] [--version] url

positional arguments:
  url              Target URL (e.g., https://example.com)

optional arguments:
  --modules        Modules to run: all, waf, tech, dns, geo, ssl, headers,
                   redirect, robots, cookies, ports, whois, subdomains, js
  --timeout        Request timeout in seconds (default: 10)
  --output         Save report to file (JSON)
  --json           Print results as JSON
  --version        Show version and exit
```

---

## Requirements

- Python 3.8+
- `requests>=2.31.0`
- `dnspython>=2.4.0`
- `python-whois>=0.9.4`

---

## Legal Disclaimer

> **For authorized testing only. Unauthorized use is illegal and unethical. Always obtain explicit written permission before scanning any system you do not own.**

---

## Author

**Sohaim** — Recon phase pentesting tooling