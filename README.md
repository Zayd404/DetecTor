<div align="center">

# 🛡️ DetecTor Framework

**Modular Attack Surface Reconnaissance & OSINT Intelligence Toolkit**

[![Version](https://shields.io)](https://github.com)
[![Python](https://shields.io)](https://python.org)
[![Platform](https://shields.io)](#installation)
[![License](https://shields.io)](#license)

*Fast, lightweight, and dependency-minimal CLI reconnaissance framework built for security researchers, penetration testers, and OSINT analysts.*

[Features](#-key-features) • [Installation](#-installation) • [Usage](#-usage) • [Architecture](#-project-architecture) • [Contributing](#-contributing) • [Support](#-support--donations)

</div>

---

## 📖 Overview

**DetecTor Framework** is a modular Command-Line Interface (CLI) toolkit designed to streamline passive and semi-active reconnaissance workflows. Built on pure Python sockets and `rich` terminal UI components, DetecTor operates reliably across restricted network environments without requiring bloated third-party wrappers or API keys for core intelligence gathering.

---

## ✨ Key Features

### 1. 🌐 Web & Infrastructure Reconnaissance
* **URL / Domain Recon (`1.1`)**
  * **DNS Resolution**: Dual-stack `A` (IPv4) and `AAAA` (IPv6) record enumeration.
  * **HTTP Security Headers Audit**: Automated grading for `HSTS`, `CSP`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy`.
  * **Technology & WAF/CDN Fingerprinting**: Detects web servers, frameworks/CMS (WordPress, Next.js, Laravel, PHP, ASP.NET), allowed HTTP methods, and perimeter defenses (Cloudflare, AWS CloudFront, Akamai, Sucuri, Imperva).
  * **SSL / TLS Inspection**: Evaluates TLS protocol versions, certificate validity periods, and expiration countdowns.
  * **Cookie & Sensitive File Discovery**: Audits `HttpOnly`/`Secure` cookie flags and checks exposure of `/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt`, `/.env`, and `/.git/HEAD`.
  * **Passive Subdomain Enumeration**: Discovers unique subdomains via Certificate Transparency & passive DNS sources.
* **IP Address Recon (`1.2`)**
  * **Network & Reverse DNS**: IPv4/IPv6 validation, address scope classification, and `PTR` record lookup.
  * **Geolocation & ASN Intelligence**: Resolves physical coordinates, ISP, organization, ASN, and infrastructure classification (*Cloud/Data Center* vs. *Proxy/VPN/Exit Node*).
  * **Port & Service Banner Grabbing**: Identifies open ports and verifies live service banners (`DNS`, `TLS`, `HTTP`, `SSH`, etc.).
  * **Direct Web Service Probe**: Inspects direct `HTTP`/`HTTPS` responses on target IP addresses.

### 2. 🕵️ People OSINT Intelligence
* **Username Profile Search (`2.1`)**
  * Verifies account existence across 12 major platforms (GitHub, GitLab, Reddit, Dev.to, Medium, Pastebin, Pinterest, Linktree, Keybase, TikTok, Instagram, X).
  * Extracts public profile metadata from **GitHub** & **GitLab** (display name, bio, organization, location, repository stats, account creation date, and public commit author emails).
* **Public Name & Dork Footprint (`2.2`)**
  * Generates logical username permutations from target full names.
  * Builds categorized Google & DuckDuckGo OSINT dork queries targeting professional profiles, social networks, source code repositories, leaked pastes, and indexed documents (`PDF`, `DOCX`, `XLSX`).

### 3. ⚙️ Operational Diagnostics & Reporting
* **System & OpSec Status (`3`)**: Verifies module readiness, network connectivity (`ONLINE/OFFLINE`), local interface IP, public exit IP (for VPN/Proxy verification), disk capacity, and report metrics.
* **Built-in Documentation (`4` & Interactive `help`)**: Comprehensive built-in user guide plus contextual `help` / `?` commands inside every target input prompt.
* **Automated Dual-Format Reporting**: Automatically exports structured **JSON** and human-readable **TXT** reports into `reports/` for every scan.

---

## Installation

### Prerequisites
* **Python 3.10+**
* **Git**

### Quick Setup (Linux / macOS / WSL)
```bash
# Clone the repository
git clone https://github.com.git
cd DetecTor

# Install required dependency
pip install -r requirements.txt || pip install rich

# Launch DetecTor
PYTHONPATH=src python3 -m detector
```

### Optional: Global CLI Command Installation
To run `detector` globally from any directory on Linux/macOS:
```bash
sudo tee /usr/local/bin/detector > /dev/null << 'LAUNCH'
#!/usr/bin/env bash
cd "$HOME/DetecTor" && PYTHONPATH=src python3 -m detector "$@"
LAUNCH
sudo chmod +x /usr/local/bin/detector
```

---

## 💻 Usage

Launch the framework and navigate through the interactive terminal menu:

```bash
detector
```

| Menu Option | Module | Example Inputs |
| :--- | :--- | :--- |
| **`1` → `1`** | URL / Domain Recon | `example.com`, `https://target.org` |
| **`1` → `2`** | IP Address Recon | `8.8.8.8`, `2606:4700:4700::1111` |
| **`2` → `1`** | Username Profile Search | `torvalds123`, `zayd404` |
| **`2` → `2`** | Public Name Search | `John Doe`, `Zanony Scarela` |
| **`3`** | System & OpSec Status | *Displays network exit IP & diagnostics* |
| **`4`** | Help & Documentation | *Displays full built-in usage guide* |

> **Tip:** Type `help` or `?` at any target input prompt to view quick syntax examples without leaving your current workflow.

---

## 🏗️ Project Architecture

```text
DetecTor/
├── README.md
├── reports/                     # Auto-generated JSON & TXT scan reports
└── src/
    └── detector/
        ├── __init__.py
        ├── __main__.py
        ├── cli.py               # Interactive CLI menu controller
        ├── common/
        │   └── system_info.py   # Environment, storage & OpSec network checks
        ├── core/
        │   ├── config.py        # Configuration loader
        │   ├── engine.py        # Core orchestration & report dispatcher
        │   └── logger.py        # Structured execution logging
        ├── handlers/
        │   ├── people_handler.py
        │   └── web_handler.py
        ├── modules/
        │   ├── people_osint/    # Username verification, metadata & dork engine
        │   └── web_recon/       # DNS, SSL, headers, WAF/CDN & raw-socket IP recon
        ├── reporting/           # JSON & TXT report formatters
        └── ui/                  # Rich tables, panels & visual components
```

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are warmly welcome! Whether you want to add new OSINT platform probes, improve WAF signatures, or enhance reporting formats:

1. **Fork** the repository.
2. Create a new feature branch (`git checkout -b feature/amazing-module`).
3. Commit your changes (`git commit -m 'Add amazing reconnaissance module'`).
4. Push to the branch (`git push origin feature/amazing-module`).
5. Open a **Pull Request**.

Please ensure your code follows the existing modular structure under `src/detector/modules/` and passes syntax checks before submitting.

---

## Support & Donations

If **DetecTor Framework** helps streamline your security research, bug bounty recon, or OSINT investigations, consider supporting its ongoing development:

* ⭐ **Star this repository** on GitHub to help others discover the project!
* ☕ **Buy Me a Coffee / Ko-fi**:`https://ko-fi.com/zanonyscarela`*(replace with your preferred link)*
* 🇮🇩 **Saweria / Trakteer**: `https://saweria.co/zayd404` *(replace with your preferred link)*
* 🪙 **Crypto ( BTC )**:`bc1qqxprcvpd5kq3y7ha485j5sqpyatuc8rphcf2ez` Feel free to open an issue or check profile bio for wallet details.

---

## ⚠️ Legal Disclaimer

**DetecTor Framework** is developed strictly for **educational purposes, authorized penetration testing, and personal security auditing**. Users are solely responsible for complying with all applicable local, national, and international laws. The author (**Zanony_Scarela**) assumes no liability for any misuse or unauthorized scanning performed with this software.

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.
