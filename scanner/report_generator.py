import json
from html import escape


def load_json(filename):
    with open(filename, "r", encoding="utf-8") as file:
        return json.load(file)


def generate_report():

    scan_data = load_json("reports/scan_results.json")
    risk_data = load_json("reports/risk_analysis.json")
    cve_data = load_json("reports/cve_results.json")

    target = escape(str(scan_data.get("target", "Unknown")))
    scan_time = escape(str(scan_data.get("scan_time", "Unknown")))

    # -----------------------------
    # Calculate statistics
    # -----------------------------

    open_ports = 0

    for host in scan_data.get("hosts", []):
        for port in host.get("ports", []):
            if port.get("state") == "open":
                open_ports += 1

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for finding in risk_data:

        risk = finding.get("risk", "").upper()

        if risk == "CRITICAL":
            critical_count += 1

        elif risk == "HIGH":
            high_count += 1

        elif risk == "MEDIUM":
            medium_count += 1

        elif risk == "LOW":
            low_count += 1

    cve_count = 0

    for result in cve_data:
        cve_count += len(result.get("cves", []))

    total_risks = (
        critical_count
        + high_count
        + medium_count
        + low_count
    )

    # -----------------------------
    # Security status
    # -----------------------------

    if critical_count > 0:
        security_status = "CRITICAL"
        status_class = "critical"
    elif high_count > 0:
        security_status = "HIGH RISK"
        status_class = "high"
    elif medium_count > 0:
        security_status = "MODERATE RISK"
        status_class = "medium"
    else:
        security_status = "LOW RISK"
        status_class = "low"

    # -----------------------------
    # HTML
    # -----------------------------

    html = f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>Cybersecurity Assessment Report</title>

<style>

/* ==============================
   GLOBAL
   ============================== */

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 0;
    background: #050b14;
    color: #d7e3f4;
    font-family: Arial, Helvetica, sans-serif;
}}

.container {{
    max-width: 1400px;
    margin: auto;
    padding: 30px;
}}

/* ==============================
   HEADER
   ============================== */

.header {{
    background:
        linear-gradient(
            135deg,
            #07111f,
            #0b1d32
        );

    border: 1px solid #123b5d;
    border-radius: 16px;
    padding: 35px;
    margin-bottom: 25px;

    box-shadow:
        0 0 30px rgba(0, 170, 255, 0.08);
}}

.logo {{
    font-size: 15px;
    color: #00e5ff;
    letter-spacing: 3px;
    font-weight: bold;
    margin-bottom: 15px;
}}

.header h1 {{
    margin: 0;
    font-size: 34px;
    color: #ffffff;
}}

.header h1 span {{
    color: #00e5ff;
}}

.header-subtitle {{
    color: #8ca4bd;
    margin-top: 10px;
    font-size: 15px;
}}

.target-info {{
    display: flex;
    flex-wrap: wrap;
    gap: 25px;
    margin-top: 25px;
}}

.info-box {{
    background: #081525;
    border: 1px solid #153a58;
    padding: 14px 20px;
    border-radius: 8px;
    min-width: 250px;
}}

.info-label {{
    display: block;
    color: #7188a0;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
}}

.info-value {{
    display: block;
    color: #00e5ff;
    margin-top: 6px;
    font-weight: bold;
}}

/* ==============================
   STATUS
   ============================== */

.status-banner {{
    display: flex;
    justify-content: space-between;
    align-items: center;

    background: #081525;
    border: 1px solid #153a58;
    border-radius: 12px;

    padding: 18px 22px;
    margin-bottom: 25px;
}}

.status-label {{
    color: #8198af;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 1px;
}}

.status {{
    padding: 8px 18px;
    border-radius: 20px;
    font-size: 13px;
    font-weight: bold;
}}

.status.critical {{
    background: rgba(255, 60, 60, 0.15);
    color: #ff4d4d;
    border: 1px solid #ff4d4d;
}}

.status.high {{
    background: rgba(255, 100, 80, 0.15);
    color: #ff735c;
    border: 1px solid #ff735c;
}}

.status.medium {{
    background: rgba(255, 180, 60, 0.15);
    color: #ffb43c;
    border: 1px solid #ffb43c;
}}

.status.low {{
    background: rgba(50, 220, 130, 0.15);
    color: #32dc82;
    border: 1px solid #32dc82;
}}

/* ==============================
   DASHBOARD
   ============================== */

.dashboard {{
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(200px, 1fr));

    gap: 16px;
    margin-bottom: 25px;
}}

.stat {{
    background: #081525;
    border: 1px solid #153a58;
    border-radius: 12px;
    padding: 22px;

    box-shadow:
        0 5px 20px rgba(0,0,0,0.2);
}}

.stat-title {{
    color: #7890a8;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
}}

.stat-value {{
    font-size: 32px;
    font-weight: bold;
    margin-top: 10px;
    color: #ffffff;
}}

.stat-description {{
    margin-top: 6px;
    color: #60778e;
    font-size: 12px;
}}

.blue {{
    color: #00e5ff;
}}

.red {{
    color: #ff4d4d;
}}

.orange {{
    color: #ffb43c;
}}

.green {{
    color: #32dc82;
}}

/* ==============================
   CARDS
   ============================== */

.card {{
    background: #081525;
    border: 1px solid #153a58;
    border-radius: 14px;
    padding: 25px;
    margin-bottom: 22px;

    box-shadow:
        0 5px 20px rgba(0,0,0,0.18);
}}

.card-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
}}

.card h2 {{
    margin: 0;
    color: #ffffff;
    font-size: 20px;
}}

.card h2::before {{
    content: "▌";
    color: #00e5ff;
    margin-right: 8px;
}}

.card-description {{
    color: #7188a0;
    font-size: 13px;
    margin-top: 7px;
}}

/* ==============================
   TABLES
   ============================== */

.table-container {{
    overflow-x: auto;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th {{
    background: #0c1d30;
    color: #7f9ab5;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
}}

th, td {{
    padding: 14px;
    border-bottom: 1px solid #142c42;
    text-align: left;
}}

td {{
    color: #c8d7e8;
    font-size: 14px;
}}

tr:hover {{
    background: #0c1d30;
}}

/* ==============================
   BADGES
   ============================== */

.badge {{
    display: inline-block;
    padding: 5px 11px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: bold;
}}

.badge-open {{
    background: rgba(50, 220, 130, 0.12);
    color: #32dc82;
    border: 1px solid #32dc82;
}}

.badge-critical {{
    color: #ff4d4d;
    background: rgba(255, 77, 77, 0.12);
}}

.badge-high {{
    color: #ff735c;
    background: rgba(255, 115, 92, 0.12);
}}

.badge-medium {{
    color: #ffb43c;
    background: rgba(255, 180, 60, 0.12);
}}

.badge-low {{
    color: #32dc82;
    background: rgba(50, 220, 130, 0.12);
}}

.badge-unknown {{
    color: #9caabd;
    background: rgba(156, 170, 189, 0.10);
}}

/* ==============================
   EMPTY STATE
   ============================== */

.empty {{
    text-align: center;
    padding: 30px;
    color: #7188a0;
}}

/* ==============================
   FOOTER
   ============================== */

.footer {{
    margin-top: 35px;
    padding: 30px;
    text-align: center;

    border-top: 1px solid #153a58;
    color: #60778e;
}}

.footer .project-name {{
    color: #00e5ff;
    font-weight: bold;
}}

.footer .author {{
    margin-top: 10px;
    color: #ffffff;
    font-size: 16px;
    font-weight: bold;
}}

.footer .author span {{
    color: #00e5ff;
}}

.footer .disclaimer {{
    margin-top: 12px;
    font-size: 11px;
    color: #4e6479;
}}

/* ==============================
   RESPONSIVE
   ============================== */

@media (max-width: 700px) {{

    .container {{
        padding: 15px;
    }}

    .header h1 {{
        font-size: 25px;
    }}

    .target-info {{
        flex-direction: column;
    }}

    .info-box {{
        min-width: auto;
    }}

    .status-banner {{
        flex-direction: column;
        align-items: flex-start;
        gap: 12px;
    }}

}}

</style>

</head>


<body>

<div class="container">


<!-- HEADER -->

<div class="header">

<div class="logo">
SECURITY OPERATIONS // NETWORK ASSESSMENT
</div>

<h1>
Network <span>Reconnaissance</span>
<br>
& Vulnerability Scanner
</h1>

<div class="header-subtitle">
Automated network discovery, service enumeration,
risk analysis and vulnerability intelligence.
</div>

<div class="target-info">

<div class="info-box">

<span class="info-label">
Target
</span>

<span class="info-value">
{target}
</span>

</div>


<div class="info-box">

<span class="info-label">
Scan Time
</span>

<span class="info-value">
{scan_time}
</span>

</div>

</div>

</div>


<!-- SECURITY STATUS -->

<div class="status-banner">

<div>

<div class="status-label">
Overall Security Assessment
</div>

<div style="margin-top:6px;color:#ffffff;">
Automated risk evaluation based on discovered services.
</div>

</div>

<div class="status {status_class}">
{security_status}
</div>

</div>


<!-- DASHBOARD -->

<div class="dashboard">


<div class="stat">

<div class="stat-title">
Open Ports
</div>

<div class="stat-value blue">
{open_ports}
</div>

<div class="stat-description">
Discovered network services
</div>

</div>


<div class="stat">

<div class="stat-title">
Critical Risks
</div>

<div class="stat-value red">
{critical_count}
</div>

<div class="stat-description">
Immediate attention required
</div>

</div>


<div class="stat">

<div class="stat-title">
High Risks
</div>

<div class="stat-value red">
{high_count}
</div>

<div class="stat-description">
High-priority findings
</div>

</div>


<div class="stat">

<div class="stat-title">
Medium Risks
</div>

<div class="stat-value orange">
{medium_count}
</div>

<div class="stat-description">
Potential exposure
</div>

</div>


<div class="stat">

<div class="stat-title">
CVEs Found
</div>

<div class="stat-value blue">
{cve_count}
</div>

<div class="stat-description">
NVD vulnerability records
</div>

</div>


</div>


<!-- OPEN PORTS -->

<div class="card">

<div class="card-header">

<div>

<h2>Network Services</h2>

<div class="card-description">
Open ports and detected service information
</div>

</div>

</div>

<div class="table-container">

<table>

<tr>

<th>Port</th>

<th>Protocol</th>

<th>State</th>

<th>Service</th>

<th>Product</th>

<th>Version</th>

</tr>
"""

    for host in scan_data.get("hosts", []):

        for port in host.get("ports", []):

            port_state = port.get("state", "unknown")

            state_class = (
                "badge-open"
                if port_state == "open"
                else "badge-unknown"
            )

            html += f"""
<tr>

<td>
<strong>{escape(str(port.get("port", "-")))}</strong>
</td>

<td>
{escape(str(port.get("protocol", "-")))}
</td>

<td>
<span class="badge {state_class}">
{escape(str(port_state).upper())}
</span>
</td>

<td>
{escape(str(port.get("service", "unknown")))}
</td>

<td>
{escape(str(port.get("product", "unknown")))}
</td>

<td>
{escape(str(port.get("version", "unknown")))}
</td>

</tr>
"""

    html += """
</table>

</div>

</div>


<!-- RISK ANALYSIS -->

<div class="card">

<div class="card-header">

<div>

<h2>Security Risk Analysis</h2>

<div class="card-description">
Rule-based assessment of exposed network services
</div>

</div>

</div>

<div class="table-container">

<table>

<tr>

<th>Port</th>

<th>Service</th>

<th>Risk Level</th>

<th>Security Assessment</th>

</tr>
"""

    if risk_data:

        for finding in risk_data:

            risk = str(
                finding.get(
                    "risk",
                    "UNKNOWN"
                )
            ).upper()

            risk_class = {
                "CRITICAL": "badge-critical",
                "HIGH": "badge-high",
                "MEDIUM": "badge-medium",
                "LOW": "badge-low"
            }.get(
                risk,
                "badge-unknown"
            )

            html += f"""
<tr>

<td>
{escape(str(finding.get("port", "-")))}
</td>

<td>
{escape(str(finding.get("service", "unknown")))}
</td>

<td>
<span class="badge {risk_class}">
{escape(risk)}
</span>
</td>

<td>
{escape(str(finding.get("reason", "No description available.")))}
</td>

</tr>
"""

    else:

        html += """
<tr>

<td colspan="4" class="empty">
No rule-based security risks were identified.
</td>

</tr>
"""

    html += """
</table>

</div>

</div>


<!-- CVE FINDINGS -->

<div class="card">

<div class="card-header">

<div>

<h2>Vulnerability Intelligence</h2>

<div class="card-description">
CVE information retrieved from the National Vulnerability Database
</div>

</div>

</div>

<div class="table-container">

<table>

<tr>

<th>Product</th>

<th>Version</th>

<th>CVE</th>

<th>Severity</th>

<th>Score</th>

</tr>
"""

    for result in cve_data:

        for cve in result.get("cves", []):

            severity = str(
                cve.get(
                    "severity",
                    "Unknown"
                )
            ).upper()

            severity_class = {
                "CRITICAL": "badge-critical",
                "HIGH": "badge-high",
                "MEDIUM": "badge-medium",
                "LOW": "badge-low"
            }.get(
                severity,
                "badge-unknown"
            )

            html += f"""
<tr>

<td>
{escape(str(result.get("product", "unknown")))}
</td>

<td>
{escape(str(result.get("version", "unknown")))}
</td>

<td>
<strong>
{escape(str(cve.get("cve_id", "Unknown")))}
</strong>
</td>

<td>

<span class="badge {severity_class}">
{escape(severity)}
</span>

</td>

<td>
{escape(str(cve.get("score", "Unknown")))}
</td>

</tr>
"""

    if cve_count == 0:

        html += """
<tr>

<td colspan="5" class="empty">

No CVEs found or software versions were unavailable.

</td>

</tr>
"""

    html += """
</table>

</div>

</div>


<!-- ASSESSMENT SUMMARY -->

<div class="card">

<div class="card-header">

<div>

<h2>Assessment Summary</h2>

<div class="card-description">
Summary of the automated security assessment
</div>

</div>

</div>

<table>

<tr>
<th>Metric</th>
<th>Result</th>
</tr>

<tr>
<td>Discovered Open Ports</td>
<td><strong>""" + str(open_ports) + """</strong></td>
</tr>

<tr>
<td>Total Risk Findings</td>
<td><strong>""" + str(total_risks) + """</strong></td>
</tr>

<tr>
<td>Critical Findings</td>
<td class="red"><strong>""" + str(critical_count) + """</strong></td>
</tr>

<tr>
<td>High Findings</td>
<td class="red"><strong>""" + str(high_count) + """</strong></td>
</tr>

<tr>
<td>Medium Findings</td>
<td class="orange"><strong>""" + str(medium_count) + """</strong></td>
</tr>

<tr>
<td>Low Findings</td>
<td class="green"><strong>""" + str(low_count) + """</strong></td>
</tr>

<tr>
<td>CVEs Identified</td>
<td><strong>""" + str(cve_count) + """</strong></td>
</tr>

</table>

</div>


<!-- FOOTER -->

<div class="footer">

<div class="project-name">
NETWORK RECONNAISSANCE & VULNERABILITY SCANNER
</div>

<div class="author">
Developed by <span>j Vikhaas Anandh</span>
</div>

<div class="disclaimer">
For authorized security testing, educational and laboratory use only.
</div>

</div>


</div>

</body>

</html>
"""

    filename = "reports/security_report.html"

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)

    print(
        f"[+] HTML report generated: {filename}"
    )


if __name__ == "__main__":
    generate_report()