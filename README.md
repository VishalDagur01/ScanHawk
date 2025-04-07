# ScanHawk 🦅

**ScanHawk** is a simple yet powerful Python-based vulnerability scanner that performs:
we also provide #Subdomains.txt# file so you can add more domain on this file. 
And all your scan will save in scan_report.txt file so you can watch it. 


- Subdomain enumeration
- Port scanning using Nmap
- XSS vulnerability detection
- Directory bruteforcing
- Report generation

🚀 How to Run

python scanhawk.py -u https://example.com --xss --dir --subdomain --port
or
python scanhawk.py url(example.com)

## 🔧 Installation

```bash
git clone https://github.com/VishalDagur01/ScanHawk.git
cd ScanHawk
pip install -r requirements.txt
