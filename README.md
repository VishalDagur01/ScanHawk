# ScanHawk 🦅

**ScanHawk** is a simple yet powerful Python-based vulnerability scanner that performs:

- Subdomain enumeration
- Port scanning using Nmap
- XSS vulnerability detection
- Directory bruteforcing
- Report generation

## 🔧 Installation

```bash
git clone https://github.com/VishalDagur01/ScanHawk.git
cd ScanHawk
pip install -r requirements.txt

🚀 How to Run

python scanhawk.py -u https://example.com --xss --dir --subdomain --port
or
python scanhawk.py url(example.com)
