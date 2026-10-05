import json
import requests
from urllib.parse import quote


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cves(product, version):

    if not product or product.lower() == "unknown":
        return []

    if not version or version.lower() == "unknown":
        return []

    keyword = f"{product} {version}"

    print(f"\n[*] Searching NVD for: {keyword}")

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 10
    }

    try:
        response = requests.get(
            NVD_API,
            params=params,
            timeout=15
        )

        response.raise_for_status()

        data = response.json()

        vulnerabilities = []

        for item in data.get("vulnerabilities", []):

            cve = item.get("cve", {})

            cve_id = cve.get("id", "Unknown")

            description = "No description available."

            descriptions = cve.get("descriptions", [])

            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", description)
                    break

            severity = "Unknown"
            score = "Unknown"

            metrics = cve.get("metrics", {})

            if "cvssMetricV40" in metrics:
                metric = metrics["cvssMetricV40"][0]
                cvss_data = metric.get("cvssData", {})

                score = cvss_data.get(
                    "baseScore",
                    "Unknown"
                )

                severity = cvss_data.get(
                    "baseSeverity",
                    "Unknown"
                )

            elif "cvssMetricV31" in metrics:
                metric = metrics["cvssMetricV31"][0]
                cvss_data = metric.get("cvssData", {})

                score = cvss_data.get(
                    "baseScore",
                    "Unknown"
                )

                severity = cvss_data.get(
                    "baseSeverity",
                    "Unknown"
                )

            vulnerabilities.append({
                "cve_id": cve_id,
                "severity": severity,
                "score": score,
                "description": description
            })

        return vulnerabilities

    except requests.RequestException as error:

        print(f"[!] NVD API request failed: {error}")

        return []


def main():

    with open(
        "reports/scan_results.json",
        "r"
    ) as file:

        scan_data = json.load(file)

    results = []

    for host in scan_data.get("hosts", []):

        for port in host.get("ports", []):

            product = port.get(
                "product",
                "unknown"
            )

            version = port.get(
                "version",
                "unknown"
            )

            if version.lower() == "unknown":

                print(
                    f"\n[-] Skipping {product}: "
                    "version unknown"
                )

                continue

            cves = search_cves(
                product,
                version
            )

            results.append({
                "host": host.get("host"),
                "port": port.get("port"),
                "product": product,
                "version": version,
                "cves": cves
            })

    with open(
        "reports/cve_results.json",
        "w"
    ) as file:

        json.dump(
            results,
            file,
            indent=4
        )

    print(
        "\n[+] CVE lookup completed."
    )

    print(
        "[+] Results saved to: "
        "reports/cve_results.json"
    )


if __name__ == "__main__":
    main()