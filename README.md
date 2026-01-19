# 🔍 VulnHunter Pro: Web Vulnerability Scanner

![Banner](https://via.placeholder.com/800x200?text=VulnHunter+Pro+-+Scan+with+confidence)  
*Advanced web vulnerability scanner built in Python for pentesters, bug bounty hunters, and DevSecOps teams.*

---

## 🚀 What is VulnHunter Pro?

**VulnHunter Pro** is an all-in-one vulnerability scanner designed to automate common web pentesting tasks and detect security flaws in modern web applications. It combines several techniques and tools into a single, high-performance CLI scanner.

It supports detection of:
- ✅ SQL Injection (SQLi)
- ✅ Cross-Site Scripting (XSS)
- ✅ Insecure security headers
- ✅ Directory and file disclosure
- ✅ Misconfigured cookies
- ✅ Weak SSL/TLS setups

Reports are generated in visual (HTML) and structured (JSON) formats, with actionable remediation tips.

---

## ⚡ Key Features

- 🔎 Detects common and advanced web vulnerabilities (OWASP Top 10)
- 📊 HTML/JSON/PDF reporting with risk scoring
- 🧠 AI-powered false positive filtering and smart payload generation
- 🧰 Integrates with Nmap, Nuclei, SQLMap, Nikto, WPScan, Gobuster, Amass
- 🚀 Multi-threaded for performance (up to 50 threads)
- 🥷 Stealth mode with WAF evasion, user-agent rotation, and delay randomization
- 🌐 Multi-language reporting (English, Spanish, French, German)
- 🔄 Supports CI/CD and REST API integration

---

## ⚙️ Installation


### 1. Clone the repository
git clone https://github.com/KiritoAkerm/vulnhunter-pro.git
cd vulnhunter-pro


### 2. Install required dependencies
pip install -r requirements.txt
(Important)
Due to PEP 668 (externally managed python environments), Kali Linux and other pentesting distributions required the use of a python virtual environment 

```bash 
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt


### 3. Verify installation
python vulnhunter.py --version

---

## 🧪 Quick Start Example

Run a basic scan against a test target:

python vulnhunter.py -u https://testphp.vulnweb.com

Expected output:

[+] Scanning: https://testphp.vulnweb.com
[!] Vulnerability found: XSS in /search.php
[✓] Report saved: reports/scan_results.html

---

## 🧩 CLI Options

Argument	Description	Example
-u URL	Scan a single target URL	-u https://example.com
-f targets.txt	Scan multiple targets from file	-f targets.txt
-o file.html	Output report file	-o report.html
--verbose	Enable verbose output	--verbose
--stealth	Enable stealth scan mode	--stealth
--language es	Set report language	--language es

---

## 📂 Report Structure

vulnhunter-pro/
├── reports/
│   ├── scan_YYYYMMDD.html        # Visual report
│   ├── scan_YYYYMMDD.json        # Structured data
│   ├── executive_summary.pdf     # Executive summary
│   └── technical_details.txt     # Scan logs
🛠 Customize Rules
You can add your own detection rules by editing rules.py:

CUSTOM_RULES = [
    {
        "name": "Custom Admin Rule",
        "pattern": r"admin\s*=\s*true",
        "severity": "HIGH"
    }
]

You can also extend or replace wordlists in /wordlists.

---

## 🔧 Advanced Use Cases

CI/CD pipeline integration (GitHub Actions, GitLab CI)

Docker support

API mode (coming soon)

Scan authenticated areas via session or header injection

Scheduled or incremental scans per project

---

## 🧠 AI Capabilities

Machine learning model to reduce false positives

Context-aware payload generation

Risk scoring with severity prediction

Exploitation chaining (experimental)

---
## ❓ Troubleshooting

Dependency issues:

pip install --upgrade -r requirements.txt
Timeouts or blocked requests:

Make sure the target is reachable and not behind strict WAF rules.

Use --stealth mode or proxy through Burp/ZAP.

No vulnerabilities detected?

Test against known vulnerable apps like:

https://testphp.vulnweb.com

http://dvwa.local

http://bwapp.local

---

## 📜 License

MIT License — Free to use and modify.
Please use ethically and only on targets you are authorized to scan.

---

## 🤝 Contributing

Pull requests are welcome!
If you have ideas, features, or fixes to propose, feel free to fork and collaborate.

---

## 🌐 Follow the Project

GitHub: VulnHunter Pro

Created by: KiritoAkerm

---

## 🚀 Happy Hacking!
#CyberSecurity #Python #Pentesting #OWASP #BugBounty #DevSecOps #OpenSource
