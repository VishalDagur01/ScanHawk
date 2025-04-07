import requests
import nmap
import urllib.parse
import argparse
from datetime import datetime

# ✅ Banner Function
def banner():
    print("\n" + "=" * 60)
    print("                🛡️  ScanHawk - Web Scanner 🛡️")
    
    print("                    Created by: VishalDagur01")
    print("=" * 60 + "\n")
  


# ✅ Subdomain Scanner (Updated for big wordlist + HTTPS support)
def subdomain_scan(domain):
    print("\n🔍 Scanning for Subdomains...\n")
    found = []
    
    try:
        with open("subdomains.txt", "r") as file:
            subdomains = file.read().splitlines()
    except FileNotFoundError:
        print("❌ subdomains.txt not found. Please add a wordlist file.")
        return []

    headers = {'User-Agent': 'Mozilla/5.0'}

    for sub in subdomains:
        for protocol in ["https", "http"]:
            url = f"{protocol}://{sub}.{domain}"
            try:
                response = requests.get(url, timeout=3, headers=headers)
                if response.status_code < 400:
                    print(f"[+] Found subdomain: {url}")
                    found.append(url)
                    break  # If found on HTTPS, skip HTTP
            except requests.exceptions.RequestException:
                continue
    return found

# ✅ Port Scanner
def port_scan(target):
    nm = nmap.PortScanner()
    print("\n🚀 Scanning Open Ports...\n")
    result = []
    nm.scan(target, '1-1000')
    for host in nm.all_hosts():
        result.append(f"Host: {host}")
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                info = f"  [+] Open Port: {port}"
                print(info)
                result.append(info)
    return result

# ✅ XSS Scanner
def xss_scan(url):
    print("\n⚡ Testing for XSS Vulnerabilities...\n")
    payloads = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>"
    ]
    found = []
    for payload in payloads:
        encoded = urllib.parse.quote(payload)
        test_url = f"{url}?q={encoded}"
        try:
            res = requests.get(test_url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            if payload in res.text:
                print(f"[!] XSS Found at {test_url}")
                found.append(test_url)
            else:
                print(f"[-] No XSS at {test_url}")
        except requests.exceptions.RequestException:
            pass
    return found

# ✅ Directory Bruteforcing
def directory_bruteforce(domain):
    print("\n📁 Scanning Common Directories...\n")
    paths = ["/admin", "/dashboard", "/login", "/cpanel", "/server-status", "/test", "/dev", "/config", "/.git", "/backup"]
    found = []
    for path in paths:
        url = f"http://{domain}{path}"
        try:
            res = requests.get(url, timeout=3, headers={'User-Agent': 'Mozilla/5.0'})
            if res.status_code not in [404]:
                print(f"[+] Found directory: {url} [Status: {res.status_code}]")
                found.append(f"{url} [Status: {res.status_code}]")
        except requests.exceptions.RequestException:
            pass
    return found

# ✅ Report Generator
def save_report(domain, subdomains, ports, xss, dirs):
    with open("scan_report.txt", "w", encoding="utf-8") as file:
        file.write(f"Scan Report for {domain}\n")
        file.write(f"Generated: {datetime.now()}\n\n")

        file.write("=== Subdomains Found ===\n")
        for s in subdomains:
            file.write(f"{s}\n")

        file.write("\n=== Open Ports ===\n")
        for p in ports:
            file.write(f"{p}\n")

        file.write("\n=== XSS Vulnerabilities ===\n")
        for x in xss:
            file.write(f"{x}\n")

        file.write("\n=== Directories Found ===\n")
        for d in dirs:
            file.write(f"{d}\n")

        file.write("\n--- END OF REPORT ---\n")

# ✅ Main
if __name__ == "__main__":
    banner()
    parser = argparse.ArgumentParser(description="Simple Vulnerability Scanner")
    parser.add_argument("domain", help="Target domain to scan")
    args = parser.parse_args()
    target = args.domain.strip()

    print(f"\n🎯 Target: {target}")

    subdomains = subdomain_scan(target)
    ports = port_scan(target)
    xss = xss_scan(f"http://{target}")
    dirs = directory_bruteforce(target)

    save_report(target, subdomains, ports, xss, dirs)

    print("\n✅ Scan completed. Results saved to 'scan_report.txt'.")
