from scanner.port_scanner import scan_ports
from scanner.risk_analyzer import analyze_scan
from scanner.cve_lookup import main as cve_lookup


def main():

    print("=" * 60)
    print("       NETWORK RECONNAISSANCE & VULNERABILITY SCANNER")
    print("=" * 60)

    target = input("\nEnter target IP address: ")

    print("\n[1/3] Starting network scan...")
    scan_ports(target)

    print("\n[2/3] Starting risk analysis...")
    analyze_scan()

    print("\n[3/3] Starting CVE lookup...")
    cve_lookup()

    print("\n" + "=" * 60)
    print("              SCAN COMPLETED")
    print("=" * 60)

    print("\nReports generated:")
    print("  → reports/scan_results.json")
    print("  → reports/risk_analysis.json")
    print("  → reports/cve_results.json")


if __name__ == "__main__":
    main()