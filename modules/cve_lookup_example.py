import requests
import time

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Get your free API key at: https://nvd.nist.gov/developers/request-an-api-key
API_KEY = "YOUR_API_KEY_HERE"

def lookup_cves(service_name, max_results=3):
    """Query NVD for CVEs related to a service name."""
    if service_name == "Unknown":
        return []

    headers = {"apiKey": API_KEY}
    params  = {
        "keywordSearch": service_name,
        "resultsPerPage": max_results,
        "startIndex": 0,
    }

    try:
        response = requests.get(NVD_API_URL, headers=headers, params=params, timeout=10)
        if response.status_code != 200:
            return []

        data = response.json()
        cves = []

        for item in data.get("vulnerabilities", []):
            cve    = item.get("cve", {})
            cve_id = cve.get("id", "N/A")

            metrics  = cve.get("metrics", {})
            severity = "Unknown"
            score    = "N/A"
            if "cvssMetricV31" in metrics:
                cvss     = metrics["cvssMetricV31"][0]["cvssData"]
                severity = cvss.get("baseSeverity", "Unknown")
                score    = cvss.get("baseScore", "N/A")
            elif "cvssMetricV2" in metrics:
                cvss     = metrics["cvssMetricV2"][0]["cvssData"]
                severity = metrics["cvssMetricV2"][0].get("baseSeverity", "Unknown")
                score    = cvss.get("baseScore", "N/A")

            descriptions = cve.get("descriptions", [])
            description  = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                "No description available"
            )

            cves.append({
                "id":          cve_id,
                "score":       score,
                "severity":    severity,
                "description": description[:120] + "..." if len(description) > 120 else description,
            })

        time.sleep(0.6)
        return cves

    except Exception:
        return []