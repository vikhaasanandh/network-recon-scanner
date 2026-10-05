import nmap
import json
from datetime import datetime


def scan_ports(target):
    scanner = nmap.PortScanner()

    print(f"\n[*] Scanning target: {target}")
    print("[*] Detecting ports, services and versions...")
    print("[*] Please wait...\n")

    scanner.scan(
        target,
        arguments="-sT -sV -F"
    )

    results = {
        "target": target,
        "scan_time": datetime.now().isoformat(),
        "hosts": []
    }

    for host in scanner.all_hosts():

        host_data = {
            "host": host,
            "status": scanner[host].state(),
            "ports": []
        }

        print(f"[+] Host: {host}")
        print(f"[+] Status: {scanner[host].state()}")
        print("-" * 60)

        for protocol in scanner[host].all_protocols():

            ports = scanner[host][protocol].keys()

            for port in sorted(ports):

                port_info = scanner[host][protocol][port]

                port_data = {
                    "port": port,
                    "protocol": protocol,
                    "state": port_info.get("state", "unknown"),
                    "service": port_info.get("name", "unknown"),
                    "product": port_info.get("product", "unknown"),
                    "version": port_info.get("version") or "unknown"
                }

                host_data["ports"].append(port_data)

                print(f"Port     : {port}")
                print(f"Protocol : {protocol}")
                print(f"State    : {port_data['state']}")
                print(f"Service  : {port_data['service']}")
                print(f"Product  : {port_data['product']}")
                print(f"Version  : {port_data['version']}")
                print("-" * 60)

        results["hosts"].append(host_data)

    # Save results
    filename = "reports/scan_results.json"

    with open(filename, "w") as file:
        json.dump(results, file, indent=4)

    print(f"\n[+] Scan results saved to: {filename}")


if __name__ == "__main__":

    target = input("Enter target IP address: ")

    scan_ports(target)
    