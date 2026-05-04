import json
import os
from urllib import error, parse, request


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_TIMEOUT = 8
DEFAULT_RESULTS_PER_PAGE = 3

NVD_QUERY_MAP = {
    21: "FTP",
    22: "OpenSSH",
    23: "Telnet",
    80: "HTTP",
    139: "NetBIOS",
    445: "SMB",
    3389: "Remote Desktop",
    "ftp": "FTP",
    "ssh": "OpenSSH",
    "telnet": "Telnet",
    "http": "HTTP",
    "https": "HTTPS",
    "netbios-ssn": "NetBIOS",
    "microsoft-ds": "SMB",
    "ms-wbt-server": "Remote Desktop",
}


def is_nvd_enabled():
    return os.getenv("NVD_API_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}


def get_nvd_query(service_name: str, port_number: int, service_version: str = ""):
    version_text = (service_version or "").strip()
    service_key = (service_name or "").strip().lower()
    if service_key in NVD_QUERY_MAP:
        base_query = NVD_QUERY_MAP[service_key]
        return f"{base_query} {version_text}".strip()
    if port_number in NVD_QUERY_MAP:
        base_query = NVD_QUERY_MAP[port_number]
        return f"{base_query} {version_text}".strip()
    if service_key and service_key != "bilinmiyor":
        return f"{service_name} {version_text}".strip()
    return None


def _read_int_setting(env_key, default_value, minimum=1):
    raw_value = os.getenv(env_key, "").strip()
    if not raw_value:
        return default_value
    try:
        value = int(raw_value)
    except ValueError:
        return default_value
    return max(minimum, value)


def fetch_nvd_cves(service_name: str, port_number: int, service_version: str = ""):
    query = get_nvd_query(service_name, port_number, service_version)
    if not query:
        return []

    results_per_page = _read_int_setting("NVD_RESULTS_PER_PAGE", DEFAULT_RESULTS_PER_PAGE)
    timeout = _read_int_setting("NVD_API_TIMEOUT", DEFAULT_TIMEOUT)
    params = parse.urlencode(
        {
            "keywordSearch": query,
            "resultsPerPage": results_per_page,
        }
    )
    url = f"{NVD_API_URL}?{params}&noRejected"
    headers = {
        "User-Agent": "akilli-rapor/1.0",
        "Accept": "application/json",
    }

    api_key = os.getenv("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key

    try:
        req = request.Request(url, headers=headers)
        with request.urlopen(req, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (error.URLError, error.HTTPError, TimeoutError, json.JSONDecodeError):
        return []

    results = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        severity = extract_severity(cve)
        results.append(
            {
                "cve_id": cve_id,
                "title": "NVD Eşleşmesi",
                "description": description[:240] if description else f"{query} için NVD kaydı bulundu.",
                "severity": severity,
                "source": "NVD API",
                "match_reason": f"NVD API üzerinde '{query}' araması yapıldığı için bu CVE eşleştirildi.",
            }
        )

    return results


def extract_severity(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        values = metrics.get(key, [])
        if not values:
            continue
        severity = values[0].get("cvssData", {}).get("baseSeverity")
        if severity:
            return severity
        severity = values[0].get("baseSeverity")
        if severity:
            return severity
    return "UNKNOWN"


def merge_cves(local_cves, online_cves):
    merged = []
    seen = set()

    for cve in local_cves + online_cves:
        cve_id = cve.get("cve_id")
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        merged.append(cve)

    return merged


def enrich_reports_with_online_cves(network_summary, host_reports):
    if not is_nvd_enabled():
        network_summary["cve_data_source"] = "Yerel eşleme"
        return

    for host in host_reports:
        total_cves = 0
        for port in host["open_ports_data"]:
            online_cves = fetch_nvd_cves(
                port.get("service"),
                port.get("port"),
                port.get("service_version", ""),
            )
            port["cves"] = merge_cves(port.get("cves", []), online_cves)
            total_cves += len(port["cves"])
        host["known_cve_count"] = total_cves

    host_index = {host["ip"]: host for host in host_reports}
    for summary_host in network_summary.get("host_list", []):
        detailed_host = host_index.get(summary_host["ip"])
        if detailed_host is not None:
            summary_host["known_cve_count"] = detailed_host["known_cve_count"]

    network_summary["hosts_with_known_cves"] = sum(
        1 for host in network_summary.get("host_list", []) if host.get("known_cve_count", 0) > 0
    )
    network_summary["total_known_cves"] = sum(
        host.get("known_cve_count", 0) for host in network_summary.get("host_list", [])
    )
    network_summary["cve_data_source"] = "NVD API + yerel eşleme"
