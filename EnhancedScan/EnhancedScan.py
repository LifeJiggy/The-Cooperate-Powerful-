# EnhancedScan Ultimate v2 - Bug Bounty Beast (EnhancedScan.py)
import requests
import argparse
import socket
import threading
import queue
import re
from urllib.parse import urlparse
import sys
from bs4 import BeautifulSoup
import time
import json
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import ssl
import random
import ipaddress
import netaddr

ASN_LOOKUP_URL = "http://ip-api.com/json/{}"

class VulnHunterProUltimateV2:
    def __init__(self, target_url, threads=10, timeout=5, verbose=False, delay=0, output_file=None):
        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.delay = delay
        self.output_file = output_file
        self.ips = set()
        self.ip_info = {}
        self.endpoints = set()
        self.vulnerabilities = {}
        self.subdomains = set()
        self.dns_records = {'A': set(), 'AAAA': set(), 'MX': set(), 'NS': set(), 'SPF': set(), 'TXT': set()}
        self.tls_info = {}
        self.neighbors = set()
        self.hosts = set()
        self.common_dirs = [
            'admin', 'login', 'wp-admin', 'backup', 'config', 'test', 'dev', 'api', 'v1', 'private', 'hidden'
        ]
        self.port_range = range(1, 1001)  # Ports 1-1000
        self.common_subs = [
            'www', 'mail', 'ftp', 'dev', 'test', 'staging', 'api', 'login', 'admin', 'blog', 'shop', 'secure',
            'vpn', 'webmail', 'portal', 'dashboard', 'app', 'forum', 'support', 'docs', 'auth', 'sso', 'account',
            'cdn', 'static'
        ]
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.port_queues = {}

    def print_banner(self, start=True):
        banner = """
        ==================================================
        |   EnhancedScan Ultimate v2 - Bug Bounty Beast |
        |        Author: Peace Stephen                  |
        |        Date: March 11, 2025                   |
        ==================================================
        """
        if start:
            print(banner + "\n[*] Scan Starting...")
        else:
            print("\n[*] Scan Completed!\n" + banner)

    def resolve_ips(self):
        domain = urlparse(self.target_url).hostname
        if not domain:
            print("[-] Invalid URL provided")
            sys.exit(1)
        
        try:
            ip_list = socket.getaddrinfo(domain, None, socket.AF_INET)
            self.ips.update([ip[4][0] for ip in ip_list])
        except socket.gaierror as e:
            if self.verbose:
                print(f"[!] socket.getaddrinfo failed: {e}")

        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domain, 'A')
            self.ips.update([str(answer) for answer in answers])
            self.dns_records['A'].update([str(answer) for answer in answers])
        except Exception as e:
            if self.verbose:
                print(f"[!] DNS A record lookup failed: {e}")

        print(f"[+] Resolved IPs: {', '.join(sorted(self.ips))}")
        for ip in self.ips:
            self.ip_info[ip] = {'ports': {}, 'asn': '', 'cname': ''}
            self.port_queues[ip] = queue.Queue()

    def get_ip_info(self, ip):
        try:
            response = requests.get(ASN_LOOKUP_URL.format(ip), timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                self.ip_info[ip]['asn'] = data.get('as', 'Unknown ASN')
            else:
                self.ip_info[ip]['asn'] = 'ASN lookup failed'
            resolver = dns.resolver.Resolver()
            try:
                answers = resolver.resolve(ipaddress.ip_address(ip).reverse_pointer, 'PTR')
                self.ip_info[ip]['cname'] = str(answers[0].target)
            except Exception:
                self.ip_info[ip]['cname'] = 'No CNAME'
        except requests.RequestException:
            self.ip_info[ip]['asn'] = 'ASN lookup failed'
            self.ip_info[ip]['cname'] = 'No CNAME'

    def enumerate_dns_records(self):
        domain = urlparse(self.target_url).hostname
        resolver = dns.resolver.Resolver()
        
        for record_type in ['AAAA', 'MX', 'NS', 'TXT']:
            try:
                answers = resolver.resolve(domain, record_type)
                self.dns_records[record_type].update([str(answer) for answer in answers])
                if self.verbose:
                    print(f"[*] Found {record_type} records: {', '.join([str(answer) for answer in answers])}")
            except Exception as e:
                if self.verbose:
                    print(f"[!] {record_type} lookup failed: {e}")

        # SPF (usually in TXT)
        for txt in self.dns_records['TXT']:
            if 'v=spf1' in txt:
                self.dns_records['SPF'].add(txt)

    def get_tls_info(self, ip):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=urlparse(self.target_url).hostname) as ssock:
                    cert = ssock.getpeercert()
                    self.tls_info[ip] = {
                        'version': ssock.version(),
                        'cipher': ssock.cipher()[0],
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter')
                    }
        except Exception as e:
            if self.verbose:
                print(f"[!] TLS/SSL info extraction failed for {ip}: {e}")
            self.tls_info[ip] = {'error': str(e)}

    def enumerate_neighbors(self, ip):
        try:
            ip_net = netaddr.IPNetwork(f"{ip}/24")
            self.neighbors.update([str(neighbor) for neighbor in ip_net.iter_hosts() if str(neighbor) != ip])
            if self.verbose:
                print(f"[*] Found {len(self.neighbors)} neighboring IPs for {ip}")
        except Exception as e:
            if self.verbose:
                print(f"[!] Neighbor enumeration failed for {ip}: {e}")

    def enumerate_hosts(self, ip):
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            self.hosts.add(hostname)
            print(f"[+] Hostname for {ip}: {hostname}")
        except socket.herror as e:
            if self.verbose:
                print(f"[!] Host enumeration failed for {ip}: {e}")

    def scan_port(self, ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = self.grab_banner(ip, port)
                vulns = self.check_port_vulnerabilities(port, banner)
                self.ip_info[ip]['ports'][port] = {'banner': banner, 'vulnerabilities': vulns}
                print(f"[+] {ip} - Open port: {port} - Banner: {banner}")
                if vulns:
                    print(f"    [!] Potential vulnerabilities: {', '.join(vulns)}")
            elif self.verbose:
                print(f"[-] {ip} - Port {port} closed")
            sock.close()
        except Exception as e:
            if self.verbose:
                print(f"[!] {ip} - Port scan error on {port}: {e}")

    def grab_banner(self, ip, port):
        try:
            if port in [80, 443]:
                protocol = 'https' if port == 443 else 'http'
                response = requests.get(f"{protocol}://{ip}", timeout=self.timeout, headers=self.headers)
                return response.headers.get('Server', 'No banner')
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((ip, port))
                banner = sock.recv(1024).decode('ascii', errors='ignore').strip()
                sock.close()
                return banner if banner else 'No banner'
        except Exception:
            return 'No banner'

    def check_port_vulnerabilities(self, port, banner):
        vulns = []
        banner_lower = banner.lower()
        if port == 21:
            if 'anonymous' in banner_lower:
                vulns.append("CVE-Anonymous: Anonymous FTP login")
            if 'vsftpd 2.3.4' in banner_lower:
                vulns.append("CVE-2011-2523: vsftpd backdoor")
        elif port == 22:
            if 'openssh' in banner_lower:
                version = re.search(r'OpenSSH_([\d.]+)', banner)
                if version and float(version.group(1)[:3]) < 7.7:
                    vulns.append("CVE-2018-15473: SSH user enumeration")
        elif port in [80, 443]:
            if 'apache' in banner_lower:
                version = re.search(r'Apache/([\d.]+)', banner)
                if version and float(version.group(1)[:3]) < 2.4:
                    vulns.append("CVE-2017-7679: Apache memory corruption")
            if 'nginx' in banner_lower:
                version = re.search(r'nginx/([\d.]+)', banner)
                if version and float(version.group(1)[:3]) < 1.14:
                    vulns.append("CVE-2019-9516: Nginx HTTP/2 DoS")
        elif port == 3306:
            if 'mysql' in banner_lower:
                version = re.search(r'([\d.]+)', banner)
                if version and float(version.group(1)[:3]) < 5.7:
                    vulns.append("CVE-2012-2122: MySQL auth bypass")
        elif port == 3389:
            if 'rdp' in banner_lower or not banner:
                vulns.append("Potential RDP exposure")
        return vulns

    def scan_ports(self):
        print("[*] Starting port scan across all IPs (1-1000)...")
        for ip in self.ips:
            for port in self.port_range:
                self.port_queues[ip].put(port)
            threads = []
            for _ in range(self.threads):
                t = threading.Thread(target=self.worker, args=(ip,))
                t.daemon = True  # Ensure threads exit if main program does
                t.start()
                threads.append(t)
            for t in threads:
                t.join()

    def worker(self, ip):
        while True:
            try:
                port = self.port_queues[ip].get_nowait()
                self.scan_port(ip, port)
                time.sleep(self.delay)
                self.port_queues[ip].task_done()
            except queue.Empty:
                break
            except Exception as e:
                if self.verbose:
                    print(f"[!] Worker error for {ip}: {e}")

    def check_endpoint(self, endpoint):
        try:
            url = f"{self.target_url}/{endpoint}"
            response = self.waf_bypass_request(url)
            if response and response.status_code in [200, 301, 302]:
                self.endpoints.add(endpoint)
                print(f"[+] Found endpoint: {url} - Status: {response.status_code}")
                self.analyze_vulnerabilities(url, response)
            elif response and response.status_code == 403:
                print(f"[*] Forbidden endpoint found: {url}")
            time.sleep(self.delay)
        except requests.RequestException as e:
            if self.verbose:
                print(f"[!] Error checking endpoint {endpoint}: {e}")

    def analyze_vulnerabilities(self, url, response):
        security_headers = {
            'X-XSS-Protection': 'Missing XSS Protection (Potential XSS risk)',
            'X-Content-Type-Options': 'Missing Content Type Options (MIME sniffing risk)',
            'Content-Security-Policy': 'Missing CSP (Potential XSS/CSRF risk)',
            'Strict-Transport-Security': 'Missing HSTS (MITM risk)'
        }
        vuln_list = self.vulnerabilities.setdefault(url, [])
        for header, message in security_headers.items():
            if header not in response.headers and message not in vuln_list:
                vuln_list.append(message)
        content = response.text.lower()
        if re.search(r'(password|secret|key|token)=[^&;\s]{4,}', content) and "Sensitive data exposure" not in vuln_list:
            vuln_list.append("Sensitive data exposure (Confirmed key-value pair)")

    def discover_endpoints(self):
        print("[*] Starting endpoint discovery...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.check_endpoint, self.common_dirs)
        self.crawl_site()

    def crawl_site(self):
        try:
            response = self.waf_bypass_request(self.target_url)
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('/'):
                        self.check_endpoint(href[1:])
        except requests.RequestException as e:
            if self.verbose:
                print(f"[!] Crawling error: {e}")

    def enumerate_subdomains(self):
        print("[*] Starting deep subdomain enumeration...")
        domain = urlparse(self.target_url).hostname
        resolver = dns.resolver.Resolver()
        
        try:
            answers = resolver.resolve(domain, 'NS')
            for rdata in answers:
                if self.verbose:
                    print(f"[*] Nameserver: {rdata.target}")
        except Exception as e:
            if self.verbose:
                print(f"[!] NS lookup error: {e}")

        def check_sub(sub):
            sub_domain = f"{sub}.{domain}"
            try:
                ip_list = socket.getaddrinfo(sub_domain, None, socket.AF_INET)
                ips = set([ip[4][0] for ip in ip_list])
                self.subdomains.add(sub_domain)
                self.ips.update(ips)
                print(f"[+] Found subdomain: {sub_domain} - IPs: {', '.join(ips)}")
                for ip in ips:
                    if ip not in self.ip_info:
                        self.ip_info[ip] = {'ports': {}, 'asn': '', 'cname': ''}
                        self.port_queues[ip] = queue.Queue()
                        self.get_ip_info(ip)
                        self.enumerate_neighbors(ip)
                        self.enumerate_hosts(ip)
            except socket.gaierror as e:
                if self.verbose:
                    print(f"[-] No DNS resolution for {sub_domain}: {e}")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_sub, self.common_subs)

    def waf_bypass_request(self, url):
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Googlebot/2.1 (+http://www.google.com/bot.html)'
        ]
        techniques = [
            lambda x: x,
            lambda x: x.replace('/', '//'),
            lambda x: f"/{random.randint(1,999)}{x}",
            lambda x: x.replace('/', '%2f'),
            lambda x: f"/*{random.randint(1,999)}*/{x}",
        ]
        for technique in techniques:
            try:
                headers = {
                    'User-Agent': random.choice(user_agents),
                    'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                    'Accept': 'text/html,application/xhtml+xml',
                    'Referer': 'https://www.google.com/'
                }
                modified_url = technique(url)
                response = requests.get(
                    modified_url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=False
                )
                if response.status_code not in [403, 429]:
                    if self.verbose:
                        print(f"[*] WAF bypassed with technique on {modified_url}")
                    return response
            except requests.RequestException:
                continue
        return None

    def save_results(self):
        if not self.output_file:
            return
        results = {
            'ips': {ip: self.ip_info[ip] for ip in self.ips},
            'endpoints': list(self.endpoints),
            'subdomains': list(self.subdomains),
            'vulnerabilities': self.vulnerabilities,
            'dns_records': {k: list(v) for k, v in self.dns_records.items()},
            'tls_info': self.tls_info,
            'neighbors': list(self.neighbors),
            'hosts': list(self.hosts)
        }
        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to {self.output_file}")

    def run(self):
        self.print_banner(start=True)
        self.resolve_ips()
        self.enumerate_subdomains()
        for ip in self.ips.copy():
            self.get_ip_info(ip)
            self.enumerate_neighbors(ip)
            self.enumerate_hosts(ip)
            self.get_tls_info(ip)
        self.enumerate_dns_records()
        self.scan_ports()
        self.discover_endpoints()
        
        print("\n=== Scan Results ===")
        for ip in sorted(self.ips):
            print(f"\nIP Address: {ip}")
            print(f"ASN: {self.ip_info[ip]['asn']}")
            print(f"CNAME: {self.ip_info[ip]['cname']}")
            print("Open Ports and Services:")
            for port, info in sorted(self.ip_info[ip]['ports'].items()):
                print(f" - Port {port}: {info['banner']}")
                if info['vulnerabilities']:
                    print(f"   Vulnerabilities: {', '.join(info['vulnerabilities'])}")
            if ip in self.tls_info:
                print("TLS/SSL Info:")
                for k, v in self.tls_info[ip].items():
                    print(f" - {k}: {v}")
        print("\nDiscovered Endpoints:")
        for endpoint in sorted(self.endpoints):
            print(f" - {endpoint}")
        print("Discovered Subdomains:")
        for sub in sorted(self.subdomains):
            print(f" - {sub}")
        print("\nDNS Records:")
        for record_type, records in self.dns_records.items():
            if records:
                print(f" - {record_type}: {', '.join(sorted(records))}")
        print("\nNeighboring IPs:")
        for neighbor in sorted(self.neighbors):
            print(f" - {neighbor}")
        print("\nHostnames:")
        for host in sorted(self.hosts):
            print(f" - {host}")
        print("\nPotential Vulnerabilities:")
        for url, vulns in sorted(self.vulnerabilities.items()):
            if vulns:
                print(f" - {url}: {', '.join(vulns)}")
        self.save_results()
        self.print_banner(start=False)

def parse_args():
    parser = argparse.ArgumentParser(description='EnhancedScan Ultimate V2 Bug Bounty Beast Author = Peace Stephen')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-d', '--delay', type=float, default=0, help='Delay between requests (seconds)')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    hunter = VulnHunterProUltimateV2(
        args.url,
        args.threads,
        args.timeout,
        args.verbose,
        args.delay,
        args.output
    )
    hunter.run()