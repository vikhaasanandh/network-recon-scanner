## 🏗️ Architecture

```text
                    Target IP
                        │
                        ▼
                ┌───────────────┐
                │ Nmap Scanner  │
                └───────┬───────┘
                        │
                        ▼
             Port + Service Detection
                        │
                        ▼
                  Version Detection
                        │
                        ▼
                scan_results.json
                        │
              ┌─────────┴─────────┐
              │                   │
              ▼                   ▼
       Risk Analyzer          CVE Lookup
              │                   │
              ▼                   ▼
     risk_analysis.json     cve_results.json
              │                   │
              └─────────┬─────────┘
                        │
                        ▼
              HTML Report Generator
                        │
                        ▼
              security_report.html
```

## ⚙️ Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/vikhaasanandh/network-recon-scanner.git
cd network-recon-scanner
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the virtual environment

**Windows PowerShell:**

```powershell
venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Install and verify Nmap

Make sure Nmap is installed on your system.

Check the installation:

```bash
nmap --version
```

### 6. Run the scanner

```bash
python main.py
```

When prompted, enter the IP address of an authorized target or laboratory machine.

### 7. View the generated report

After the scan completes, the following reports are generated:

```text
reports/
├── scan_results.json
├── risk_analysis.json
├── cve_results.json
└── security_report.html
```

Open the generated report:

```text
reports/security_report.html
```

> ⚠️ Only scan systems that you own or have explicit permission to test.