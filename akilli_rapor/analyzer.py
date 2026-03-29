import xml.etree.ElementTree as ET

from scanner import XML_DOSYASI


PORT_RULES = {
    21: {
        "service_category": "Dosya Aktarımı",
        "risk": "Orta",
        "recommendation": "FTP yerine SFTP veya FTPS kullanılması önerilir.",
    },
    22: {
        "service_category": "Uzak Erişim",
        "risk": "Orta",
        "recommendation": "SSH erişimi güçlü parola ve mümkünse anahtar tabanlı kimlik doğrulama ile korunmalıdır.",
    },
    23: {
        "service_category": "Uzak Erişim",
        "risk": "Yüksek",
        "recommendation": "Telnet yerine SSH kullanılmalıdır.",
    },
    80: {
        "service_category": "Web Servisi",
        "risk": "Düşük",
        "recommendation": "Mümkünse HTTPS kullanımı tercih edilmelidir.",
    },
    135: {
        "service_category": "Sistem Servisi",
        "risk": "Orta",
        "recommendation": "Bu servis gerekmiyorsa ağ erişimi sınırlandırılmalıdır.",
    },
    139: {
        "service_category": "Dosya Paylaşımı",
        "risk": "Yüksek",
        "recommendation": "NetBIOS erişimi gerekmiyorsa kapatılmalı veya yerel ağ ile sınırlandırılmalıdır.",
    },
    443: {
        "service_category": "Web Servisi",
        "risk": "Düşük",
        "recommendation": "HTTPS yapılandırmasının güncel ve güvenli olduğundan emin olunmalıdır.",
    },
    445: {
        "service_category": "Dosya Paylaşımı",
        "risk": "Yüksek",
        "recommendation": "SMB erişimi firewall ile sınırlandırılmalı ve yalnızca gerekli cihazlara açık olmalıdır.",
    },
    3389: {
        "service_category": "Uzak Erişim",
        "risk": "Yüksek",
        "recommendation": "RDP erişimi VPN arkasına alınmalı ve firewall ile korunmalıdır.",
    },
}

VULNERABILITY_RULES = {
    21: [
        {
            "cve_id": "CVE-2011-2523",
            "title": "vsFTPd Backdoor",
            "description": "Eski veya yanlış yapılandırılmış FTP servislerinde uzaktan komut çalıştırma riski görülebilir.",
            "match_reason": "FTP servisi tespit edildiği için bu CVE yerel servis kuralından önerildi.",
        }
    ],
    22: [
        {
            "cve_id": "CVE-2018-15473",
            "title": "OpenSSH User Enumeration",
            "description": "Bazı OpenSSH sürümlerinde kullanıcı adı doğrulama davranışı bilgi sızdırabilir.",
            "match_reason": "SSH servisi tespit edildiği için bu CVE yerel servis kuralından önerildi.",
        }
    ],
    445: [
        {
            "cve_id": "CVE-2017-0144",
            "title": "EternalBlue / SMBv1",
            "description": "SMBv1 kullanan eski Windows sistemlerde uzaktan kod çalıştırma riski olabilir.",
            "match_reason": "SMB servisi tespit edildiği için bu CVE yerel servis kuralından önerildi.",
        }
    ],
    3389: [
        {
            "cve_id": "CVE-2019-0708",
            "title": "BlueKeep / RDP",
            "description": "Eski RDP servislerinde kimlik doğrulama öncesi kritik uzaktan kod çalıştırma açığı bulunabilir.",
            "match_reason": "RDP servisi tespit edildiği için bu CVE yerel servis kuralından önerildi.",
        }
    ],
}

SERVICE_VULNERABILITY_RULES = {
    "ftp": VULNERABILITY_RULES[21],
    "ssh": VULNERABILITY_RULES[22],
    "microsoft-ds": VULNERABILITY_RULES[445],
    "netbios-ssn": VULNERABILITY_RULES[445],
    "ms-wbt-server": VULNERABILITY_RULES[3389],
}

VERSION_BASED_RULES = [
    {
        "match": lambda port, service_name, service_version: "apache" in service_version.lower() and "2.4.49" in service_version.lower(),
        "cves": [
            {
                "cve_id": "CVE-2021-41773",
                "title": "Apache HTTP Server 2.4.49 Path Traversal",
                "description": "Apache HTTP Server 2.4.49 sürümünde dosya yolu geçişi ve bazı yapılandırmalarda uzaktan kod çalıştırma riski bulunabilir.",
                "severity": "HIGH",
                "source": "Yerel sürüm kuralı",
                "match_reason": "Apache 2.4.49 görüldüğü için bu CVE yerel sürüm kuralından önerildi.",
            }
        ],
    },
    {
        "match": lambda port, service_name, service_version: "openssh" in service_version.lower() and "7." in service_version.lower(),
        "cves": [
            {
                "cve_id": "CVE-2018-15473",
                "title": "OpenSSH 7.x User Enumeration",
                "description": "OpenSSH 7.x ailesindeki bazı sürümlerde kullanıcı doğrulama davranışı bilgi sızdırabilir.",
                "severity": "MEDIUM",
                "source": "Yerel sürüm kuralı",
                "match_reason": "OpenSSH 7.x görüldüğü için bu CVE yerel sürüm kuralından önerildi.",
            }
        ],
    },
    {
        "match": lambda port, service_name, service_version: port == 445 and "smbv1" in service_version.lower(),
        "cves": [
            {
                "cve_id": "CVE-2017-0144",
                "title": "SMBv1 EternalBlue Exposure",
                "description": "SMBv1 tespiti eski Windows hedeflerde EternalBlue benzeri kritik uzaktan kod çalıştırma risklerini işaret edebilir.",
                "severity": "CRITICAL",
                "source": "Yerel sürüm kuralı",
                "match_reason": "SMBv1 görüldüğü için bu CVE yerel sürüm kuralından önerildi.",
            }
        ],
    },
]

BRUTE_FORCE_PORT_RULES = {
    21: "FTP servisi açık olduğu için brute-force saldırı riski vardır.",
    22: "SSH servisi açık olduğu için brute-force saldırı riski vardır.",
    3389: "RDP servisi açık olduğu için brute-force saldırı riski vardır.",
}


def get_port_info(port_number: int) -> dict:
    return PORT_RULES.get(
        port_number,
        {
            "service_category": "Bilinmiyor",
            "risk": "Bilinmiyor",
            "recommendation": "Bu servis için manuel güvenlik değerlendirmesi yapılmalıdır.",
        },
    )


def calculate_general_risk(high_count: int, medium_count: int, low_count: int) -> str:
    if high_count > 0:
        return "Yüksek"
    if medium_count > 0:
        return "Orta"
    if low_count > 0:
        return "Düşük"
    return "Bilinmiyor"


def calculate_host_score(high_count: int, medium_count: int, low_count: int) -> int:
    return (high_count * 3) + (medium_count * 2) + low_count


def detect_os(host) -> str:
    os_node = host.find("os")
    if os_node is None:
        return "Bilinmiyor"

    best_match = None
    best_accuracy = -1
    for osmatch in os_node.findall("osmatch"):
        try:
            accuracy = int(osmatch.get("accuracy", "0"))
        except ValueError:
            accuracy = 0
        if accuracy > best_accuracy:
            best_accuracy = accuracy
            best_match = osmatch.get("name")

    return best_match or "Bilinmiyor"


def normalize_os_family(os_name: str) -> str:
    lowered = (os_name or "").lower()
    if "windows" in lowered:
        return "windows"
    if "linux" in lowered or "ubuntu" in lowered or "debian" in lowered or "centos" in lowered:
        return "linux"
    if "router" in lowered or "switch" in lowered or "embedded" in lowered:
        return "network"
    return "unknown"


def elevate_risk(risk: str) -> str:
    if risk == "Düşük":
        return "Orta"
    if risk == "Orta":
        return "Yüksek"
    return risk


def adjust_risk_by_os(port_number: int, risk: str, os_name: str):
    os_family = normalize_os_family(os_name)

    if os_family == "windows" and port_number in {135, 139, 445, 3389}:
        return elevate_risk(risk), "Windows sistemlerde bu port daha yüksek saldırı yüzeyi oluşturabilir."
    if os_family == "linux" and port_number in {22, 21}:
        return elevate_risk(risk), "Linux sistemlerde bu servis yanlış yapılandırılırsa uzaktan erişim riski artabilir."
    if os_family == "network" and port_number in {23, 80, 443}:
        return elevate_risk(risk), "Router/ağ cihazlarında yönetim servislerinin açık olması riski artırabilir."

    return risk, "OS etkisi yok"


def get_version_based_cves(port_number: int, service_name: str, service_version: str):
    matches = []
    for rule in VERSION_BASED_RULES:
        if rule["match"](port_number, service_name, service_version):
            matches.extend(dict(item) for item in rule["cves"])
    return matches


def merge_cve_entries(*cve_groups):
    merged = []
    seen = set()

    for group in cve_groups:
        for cve in group:
            cve_id = cve.get("cve_id")
            if not cve_id or cve_id in seen:
                continue
            seen.add(cve_id)
            merged.append(cve)

    return merged


def get_known_cves(port_number: int, service_name: str, service_version: str = ""):
    service_key = (service_name or "").lower()
    service_cves = SERVICE_VULNERABILITY_RULES.get(service_key)
    if service_cves is None:
        service_cves = VULNERABILITY_RULES.get(port_number, [])

    normalized_service_cves = []
    for cve in service_cves:
        item = dict(cve)
        item.setdefault("severity", "Bilinmiyor")
        item.setdefault("source", "Yerel servis kuralı")
        item.setdefault("match_reason", f"{service_name} servisi tespit edildiği için bu CVE yerel servis kuralından önerildi.")
        normalized_service_cves.append(item)

    version_cves = get_version_based_cves(port_number, service_name, service_version)
    return merge_cve_entries(normalized_service_cves, version_cves)


def get_bruteforce_risk_note(port_number: int):
    return BRUTE_FORCE_PORT_RULES.get(port_number, "Belirgin brute-force riski tespit edilmedi.")


def build_service_version(service):
    if service is None:
        return "Bilinmiyor", "Bilinmiyor", "Bilinmiyor"

    service_name = service.get("name") or "Bilinmiyor"
    product = service.get("product") or ""
    version = service.get("version") or ""
    extrainfo = service.get("extrainfo") or ""

    parts = [part for part in (product, version, extrainfo) if part]
    if parts:
        detected = " ".join(parts)
    else:
        detected = service_name

    return service_name, product or "Bilinmiyor", detected


def _load_xml_root():
    try:
        tree = ET.parse(XML_DOSYASI)
        return tree.getroot()
    except ET.ParseError:
        if not XML_DOSYASI or not ET:
            raise

    try:
        with open(XML_DOSYASI, "r", encoding="utf-8", errors="ignore") as file:
            raw_xml = file.read()
    except OSError as error:
        raise ValueError(f"XML dosyasi okunamadi: {error}") from error

    cleaned_xml = raw_xml.lstrip("\ufeff")
    closing_tag = "</nmaprun>"
    closing_index = cleaned_xml.rfind(closing_tag)
    if closing_index != -1:
        cleaned_xml = cleaned_xml[: closing_index + len(closing_tag)]

    try:
        return ET.fromstring(cleaned_xml)
    except ET.ParseError as error:
        raise ValueError(
            "Nmap XML cikti dosyasi bozuk veya eksik. Tarama yeniden calistirilmali."
        ) from error


def parse_results():
    root = _load_xml_root()

    all_hosts_summary = []
    host_reports = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        address = host.find("address")
        ip = address.get("addr") if address is not None else "Bilinmiyor"
        detected_os = detect_os(host)

        total_open_ports = 0
        total_filtered_ports = 0
        high_risk_count = 0
        medium_risk_count = 0
        low_risk_count = 0
        known_cve_count = 0
        brute_force_risk_count = 0
        open_ports_data = []

        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                state = port.find("state")
                service = port.find("service")

                if state is None:
                    continue

                port_state = state.get("state")
                if port_state == "filtered":
                    total_filtered_ports += 1
                    continue

                if port_state != "open":
                    continue

                port_id = int(port.get("portid"))
                protocol = port.get("protocol")
                service_name, service_product, detected_version = build_service_version(service)
                port_info = get_port_info(port_id)
                risk = port_info["risk"]
                adjusted_risk, os_risk_note = adjust_risk_by_os(port_id, risk, detected_os)
                known_cves = get_known_cves(port_id, service_name, detected_version)
                brute_force_note = get_bruteforce_risk_note(port_id)
                has_brute_force_risk = port_id in BRUTE_FORCE_PORT_RULES

                total_open_ports += 1
                known_cve_count += len(known_cves)
                if has_brute_force_risk:
                    brute_force_risk_count += 1

                if adjusted_risk == "Yüksek":
                    high_risk_count += 1
                elif adjusted_risk == "Orta":
                    medium_risk_count += 1
                elif adjusted_risk == "Düşük":
                    low_risk_count += 1

                open_ports_data.append(
                    {
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "service_product": service_product,
                        "service_version": detected_version,
                        "category": port_info["service_category"],
                        "risk": adjusted_risk,
                        "base_risk": risk,
                        "os_risk_note": os_risk_note,
                        "brute_force_note": brute_force_note,
                        "has_brute_force_risk": has_brute_force_risk,
                        "recommendation": port_info["recommendation"],
                        "cves": known_cves,
                    }
                )

        general_risk = calculate_general_risk(high_risk_count, medium_risk_count, low_risk_count)
        host_score = calculate_host_score(high_risk_count, medium_risk_count, low_risk_count)

        all_hosts_summary.append(
            {
                "ip": ip,
                "detected_os": detected_os,
                "general_risk": general_risk,
                "score": host_score,
                "open_ports": total_open_ports,
                "filtered_ports": total_filtered_ports,
                "firewall_detected": total_filtered_ports > 0,
                "brute_force_risk_count": brute_force_risk_count,
                "known_cve_count": known_cve_count,
            }
        )
        host_reports.append(
            {
                "ip": ip,
                "detected_os": detected_os,
                "total_open_ports": total_open_ports,
                "total_filtered_ports": total_filtered_ports,
                "firewall_detected": total_filtered_ports > 0,
                "brute_force_risk_count": brute_force_risk_count,
                "high_risk_count": high_risk_count,
                "medium_risk_count": medium_risk_count,
                "low_risk_count": low_risk_count,
                "known_cve_count": known_cve_count,
                "general_risk": general_risk,
                "host_score": host_score,
                "open_ports_data": open_ports_data,
            }
        )

    total_hosts = len(all_hosts_summary)
    high_risk_hosts = sum(1 for host in all_hosts_summary if host["general_risk"] == "Yüksek")
    medium_risk_hosts = sum(1 for host in all_hosts_summary if host["general_risk"] == "Orta")
    low_risk_hosts = sum(1 for host in all_hosts_summary if host["general_risk"] == "Düşük")
    hosts_with_known_cves = sum(1 for host in all_hosts_summary if host["known_cve_count"] > 0)
    total_known_cves = sum(host["known_cve_count"] for host in all_hosts_summary)
    firewall_detected_hosts = sum(1 for host in all_hosts_summary if host["firewall_detected"])
    total_filtered_ports = sum(host["filtered_ports"] for host in all_hosts_summary)
    brute_force_risk_hosts = sum(1 for host in all_hosts_summary if host["brute_force_risk_count"] > 0)

    most_risky_host = "Yok"
    if all_hosts_summary:
        risky = max(all_hosts_summary, key=lambda host: host["score"])
        most_risky_host = f"{risky['ip']} (Skor: {risky['score']}, Açık Port: {risky['open_ports']})"

    network_summary = {
        "total_hosts": total_hosts,
        "high_risk_hosts": high_risk_hosts,
        "medium_risk_hosts": medium_risk_hosts,
        "low_risk_hosts": low_risk_hosts,
        "hosts_with_known_cves": hosts_with_known_cves,
        "total_known_cves": total_known_cves,
        "firewall_detected_hosts": firewall_detected_hosts,
        "total_filtered_ports": total_filtered_ports,
        "brute_force_risk_hosts": brute_force_risk_hosts,
        "most_risky_host": most_risky_host,
        "host_list": all_hosts_summary,
    }

    return network_summary, host_reports
