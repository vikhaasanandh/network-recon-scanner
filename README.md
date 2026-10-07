# 🔐 Network Reconnaissance & Vulnerability Scanner

A Python-based cybersecurity tool for network reconnaissance, service detection, security risk analysis, CVE lookup, and automated HTML security reporting.

> ⚠️ This tool is intended for authorized security testing, personal labs, and controlled environments only.

---

## 📌 Overview

Network Reconnaissance & Vulnerability Scanner is a cybersecurity tool developed using Python and Nmap.

The tool performs network reconnaissance against an authorized target and provides:

- Open port detection
- Service identification
- Software/product detection
- Version detection
- Security risk analysis
- CVE lookup using the NVD API
- JSON result generation
- Automated HTML security reports

---

## 🎯 Objectives

The main objectives of this project are:

1. Identify exposed network services.
2. Detect open TCP ports.
3. Identify running services and products.
4. Perform basic security risk classification.
5. Search for known vulnerabilities when reliable software versions are available.
6. Generate structured security reports.
7. Demonstrate practical cybersecurity and Python automation skills.

---

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
   risk_analysis.json       cve_results.json
              │                   │
              └─────────┬─────────┘
                        │
                        ▼
              HTML Report Generator
                        │
                        ▼
             security_report.html


---

## ⚙️ Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/vikhaasanandh/network-recon-scanner.git
cd network-recon-scanner


### 2. Create a virtual environment

```bash
python -m venv venv

### 3. Activate the virtual environment

**Windows PowerShell:**

```powershell
venv\Scripts\Activate.ps1

### 4. Install dependencies

```bash
pip install -r requirements.txt

### 5. Install and verify Nmap

Make sure Nmap is installed on your system.

Check the installation:

```bash
nmap --version

### 6. Run the scanner

```bash
python main.py

### 7. View the generated report

After the scan completes, the following reports are generated:

```text
reports/
├── scan_results.json
├── risk_analysis.json
├── cve_results.json
└── security_report.html