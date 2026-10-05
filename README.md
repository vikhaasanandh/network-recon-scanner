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