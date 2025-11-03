# SiteShow

![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg) ![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

## 🔍 Overview

**SiteShow** is a powerful, automated Web & API vulnerability scanner designed for penetration testers, bug bounty hunters, developers, and security learners. It performs intelligent crawling, deep vulnerability testing, CVE fingerprinting, and produces clean HTML/JSON reports to help you find and fix real-world security issues.

## ⚙️ Features

- Smart crawling to discover pages, forms, and API endpoints
- Detects XSS, SQLi (error/blind/time), Command Injection, Path Traversal, SSRF, XXE, IDOR, Open Redirects
- Checks CSRF, CORS misconfigurations, security headers, insecure cookies, and session handling
- Sensitive data discovery (API keys, credentials, private keys)
- Built-in CVE detection engine for common stacks (Apache, Nginx, PHP, WordPress, Drupal, Spring, Log4j)
- API security tests: exposed endpoints, missing rate limiting, mass assignment
- Multi-threaded scanning and colorized console logging
- Generates professional HTML and JSON reports with severity, payloads, and remediation tips

## ⚙️ Installation

> Requirements file will be added soon. For now, ensure Python 3.8+ is installed.

```bash
# Update package list
sudo apt update

# Install Python and pip (if not already installed)
sudo apt install python3 python3-pip -y

# Install required system dependencies
sudo apt install build-essential python3-dev -y
```

## 🚀 Quick Start

**Author:** TricksterClown02

```bash
pip3 install requests beautifulsoup4 urllib3 lxml

#if doed not work the try
pip3 install requests beautifulsoup4 urllib3 lxml --break-system-packages

**Run the scanner:**

python site_show.py
```

> Tip: Run against a target you own or have explicit permission to test.

## 📄 Output & Reports

- HTML report (e.g., `security_report_YYYYMMDD_HHMMSS.html`)
- JSON report (same name, `.json`)

Reports include vulnerability details, severity breakdown, CVE findings, and recommended fixes.

## 🛡️ Use Cases

- Bug bounty hunts
- Penetration testing engagements
- DevSecOps scanning for staging environments
- Security training and research

## 🖼️ Example (Report Preview)

<img width="1918" height="1131" alt="Screenshot From 2025-11-02 17-37-55" src="https://github.com/user-attachments/assets/652c5384-6f81-4095-bb35-1826ce4a2552" />


## 🤝 Contributing

Contributions, issue reports, and feature requests are welcome. Please open issues or PRs on this repository.

## 📜 License

This project is distributed under the **MIT License**. See the `LICENSE` file for details.
