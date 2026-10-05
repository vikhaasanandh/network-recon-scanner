import json


def load_json(filename):
    with open(filename, "r", encoding="utf-8") as file:
        return json.load(file)


def generate_report():

    scan_data = load_json("reports/scan_results.json")
    risk_data = load_json("reports/risk_analysis.json")
    cve_data = load_json("reports/cve_results.json")

    target = scan_data.get("target", "Unknown")
    scan_time = scan_data.get("scan_time", "Unknown")

    # Count open ports
    open_ports = 0

    for host in scan_data.get("hosts", []):
        for port in host.get("ports", []):
            if port.get("state") == "open":
                open_ports += 1

    # Count risk levels
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

    # Count CVEs
    cve_count = 0

    for result in cve_data:
        cve_count += len(result.get("cves", []))

    html = f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>Network Security Scan Report</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    font-family: Arial, sans-serif;
    background: #f3f4f6;
    margin: 0;
    padding: 30px;
    color: #111827;
}}

.container {{
    max-width: 1200px;
    margin: auto;
}}

.header {{
    background: #111827;
    color: white;
    padding: 30px;
    border-radius: 12px;
    margin-bottom: 20px;
}}

.header h1 {{
    margin-top: 0;
}}

.header p {{
    margin: 8px 0;
}}

.dashboard {{
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(180px, 1fr));
    gap: 15px;
    margin-bottom: 20px;
}}

.stat {{
    background: white;
    padding: 22px;
    border-radius: 10px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    text-align: center;
}}

.stat h3 {{
    margin: 0;
    color: #6b7280;
    font-size: 15px;
}}

.stat p {{
    font-size: 32px;
    font-weight: bold;
    margin: 10px 0 0;
}}

.critical {{
    color: #991b1b;
    font-weight: bold;
}}

.high {{
    color: #dc2626;
    font-weight: bold;
}}

.medium {{
    color: #d97706;
    font-weight: bold;
}}

.low {{
    color: #16a34a;
    font-weight: bold;
}}

.card {{
    background: white;
    padding: 25px;
    margin-bottom: 20px;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
}}

.card h2 {{
    margin-top: 0;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th {{
    background: #f3f4f6;
}}

th, td {{
    padding: 13px;
    border-bottom: 1px solid #e5e7eb;
    text-align: left;
}}

tr:hover {{
    background: #f9fafb;
}}

.footer {{
    text-align: center;
    color: #6b7280;
}}

.badge {{
    display: inline-block;
    padding: 5px 10px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: bold;
}}

</style>

</head>


<body>

<div class="container">


<div class="header">

<h1>Network Security Scan Report</h1>

<p>
<strong>Target:</strong> {target}
</p>

<p>
<strong>Scan Time:</strong> {scan_time}
</p>

</div>


<div class="dashboard">


<div class="stat">

<h3>Open Ports</h3>

<p>{open_ports}</p>

</div>


<div class="stat">

<h3>Critical Risks</h3>

<p class="critical">{critical_count}</p>

</div>


<div class="stat">

<h3>High Risks</h3>

<p class="high">{high_count}</p>

</div>


<div class="stat">

<h3>Medium Risks</h3>

<p class="medium">{medium_count}</p>

</div>


<div class="stat">

<h3>CVEs Found</h3>

<p>{cve_count}</p>

</div>


</div>


<div class="card">

<h2>Open Ports</h2>

<table>

<tr>

<th>Port</th>

<th>Protocol</th>

<th>Service</th>

<th>Product</th>

<th>Version</th>

</tr>
"""

    for host in scan_data.get("hosts", []):

        for port in host.get("ports", []):

            html += f"""
<tr>

<td>{port.get("port")}</td>

<td>{port.get("protocol")}</td>

<td>{port.get("service")}</td>

<td>{port.get("product")}</td>

<td>{port.get("version")}</td>

</tr>
"""

    html += """
</table>

</div>


<div class="card">

<h2>Security Risk Analysis</h2>

<table>

<tr>

<th>Port</th>

<th>Service</th>

<th>Risk</th>

<th>Reason</th>

</tr>
"""

    for finding in risk_data:

        risk = finding.get("risk", "UNKNOWN")

        risk_class = risk.lower()

        html += f"""
<tr>

<td>{finding.get("port")}</td>

<td>{finding.get("service")}</td>

<td class="{risk_class}">
{risk}
</td>

<td>{finding.get("reason")}</td>

</tr>
"""

    html += """
</table>

</div>


<div class="card">

<h2>CVE Findings</h2>

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

            severity = cve.get(
                "severity",
                "Unknown"
            )

            html += f"""
<tr>

<td>{result.get("product")}</td>

<td>{result.get("version")}</td>

<td>{cve.get("cve_id")}</td>

<td>{severity}</td>

<td>{cve.get("score")}</td>

</tr>
"""

    if cve_count == 0:

        html += """
<tr>

<td colspan="5">
No CVEs found or software versions were unavailable.
</td>

</tr>
"""

    html += """
</table>

</div>


<div class="card footer">

<p>
Generated by
<strong>
Network Reconnaissance & Vulnerability Scanner
</strong>
</p>

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