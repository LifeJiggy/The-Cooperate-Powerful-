README.md

# EnhancedScan - Ultimate Bug Bounty Scanner

![EnhancedScan Logo](https://via.placeholder.com/150) <!-- Add a cool logo later! -->

**EnhancedScan** is a powerful, multi-threaded vulnerability scanner designed for bug bounty hunters and security researchers. Built with love and teamwork, this tool unleashes a flood of actionable intelligence on your target—IP enumeration, subdomain discovery, port scanning (1-1000), endpoint crawling, DNS/TLS/SSL analysis, neighboring IP detection, and host enumeration—all wrapped in a robust, extensible Python script. Whether you're hunting for CVEs, misconfigurations, or hidden assets, *EnhancedScan* has your back.

## Features

- **IP Resolution**: Resolves multiple IPs using `socket.getaddrinfo` and DNS A records.
- **Subdomain Enumeration**: Brute-forces subdomains with a comprehensive wordlist, feeding additional IPs into the scan.
- **Port Scanning**: Scans ports 1-1000 across all discovered IPs with banner grabbing and vulnerability checks (e.g., CVE-2018-15473 for SSH).
- **Endpoint Discovery**: Crawls the target for hidden directories and endpoints, bypassing WAFs with advanced techniques.
- **DNS Records**: Extracts A, AAAA, MX, NS, TXT, and SPF records for deep domain insight.
- **TLS/SSL Analysis**: Pulls TLS version, cipher, issuer, subject, and validity dates from HTTPS services.
- **Neighboring IPs**: Enumerates /24 neighbors for each IP to uncover related infrastructure.
- **Host Enumeration**: Reverse-looks up hostnames for all IPs.
- **Vulnerability Detection**: Identifies missing security headers, sensitive data exposure, and known CVEs.
- **Output**: Saves results in a structured JSON file for easy analysis.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/[YourUsername]/EnhancedScan.git
   cd EnhancedScan

Install Dependencies:
bash

pip install -r requirements.txt

Run the Script:
bash

python EnhancedScan.py -u https://example.com -v -t 20 -d 0.1 -o results.json

Requirements
See requirements.txt for the full list. Key dependencies include:
Python 3.8+

requests, dnspython, beautifulsoup4, netaddr

Usage
bash

python EnhancedScan.py -u <target_url> [options]

Options
-u, --url: Target URL (required, e.g., https://hackerone.com).

-t, --threads: Number of threads (default: 10).

-o, --output: Output JSON file (e.g., results.json).

--timeout: Request timeout in seconds (default: 5).

-v, --verbose: Enable verbose output for debugging.

-d, --delay: Delay between requests in seconds (default: 0).

Example
bash

python EnhancedScan.py -u https://hackerone.com -v -t 20 -d 0.1 -o hackerone_results.json

Sample Output

IP Address: 104.18.36.214
ASN: AS13335 Cloudflare, Inc.
CNAME: No CNAME
Open Ports and Services:
 - Port 80: cloudflare
 - Port 443: cloudflare
TLS/SSL Info:
 - version: TLSv1.3
 - cipher: TLS_AES_256_GCM_SHA384

Discovered Subdomains:
 - api.hackerone.com
 - www.hackerone.com

DNS Records:
 - A: 104.18.36.214, 172.64.151.42
 - MX: aspmx.l.google.com

Contributing
I’d love your feedback and contributions! Whether it’s new features, bug fixes, or just ideas to make EnhancedScan even better, here’s how to get involved:
Fork the repo.

Create a feature branch (git checkout -b feature/awesome-idea).

Commit your changes (git commit -m "Added awesome idea").

Push to your branch (git push origin feature/awesome-idea).

Open a Pull Request.

Feel free to open issues for bugs or suggestions—we’re all about community vibes!
Credits
Built with passion by [YourUsername] and an amazing AI teammate at xAI. Inspired by the bug bounty community’s relentless pursuit of security.
License
MIT License—use it, tweak it, share it. Just give us a shoutout if it helps you score a bounty! 
Happy hunting, and may your scans uncover epic vulns!

---

### requirements.txt

```plaintext
requests>=2.28.0
dnspython>=2.2.1
beautifulsoup4>=4.11.1
netaddr>=0.8.0
