import json


RISK_RULES = {
    21: {
        "service": "FTP",
        "risk": "HIGH",
        "reason": "FTP may transmit credentials without encryption."
    },
    23: {
        "service": "Telnet",
        "risk": "CRITICAL",
        "reason": "Telnet transmits data, including credentials, without encryption."
    },
    445: {
        "service": "SMB",
        "risk": "HIGH",
        "reason": "SMB exposed to untrusted networks can increase attack surface."
    },
    5432: {
        "service": "PostgreSQL",
        "risk": "MEDIUM",
        "reason": "Database service should not normally be exposed to untrusted networks."
    },
    3389: {
        "service": "RDP",
        "risk": "HIGH",
        "reason": "RDP exposure can increase the risk of unauthorized remote access."
    }
}


def analyze_scan():

    with open("reports/scan_results.json", "r") as file:
        data = json.load(file)

    findings = []

    for host in data["hosts"]:

        for port_info in host["ports"]:

            port = port_info["port"]

            if port in RISK_RULES:

                rule = RISK_RULES[port]

                finding = {
                    "host": host["host"],
                    "port": port,
                    "service": rule["service"],
                    "risk": rule["risk"],
                    "reason": rule["reason"]
                }

                findings.append(finding)

    with open("reports/risk_analysis.json", "w") as file:
        json.dump(findings, file, indent=4)

    print("\n[+] Risk analysis completed.")
    print("[+] Results saved to: reports/risk_analysis.json")

    for finding in findings:

        print(
            f"\n[{finding['risk']}] "
            f"{finding['service']} "
            f"(Port {finding['port']})"
        )

        print(f"Reason: {finding['reason']}")


if __name__ == "__main__":
    analyze_scan()