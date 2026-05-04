import xml.etree.ElementTree as ET

from scanner import XML_DOSYASI


PORT_RULES = {
    21: {
        "service_category": "Dosya Aktarimi",
        "risk": "Orta",
        "recommendation": "FTP yerine SFTP veya FTPS kullanilmasi onerilir.",
    },
    22: {
        "service_category": "Uzak Erisim",
        "risk": "Orta",
        "recommendation": "SSH erisimi guclu parola ve mumkunse anahtar tabanli kimlik dogrulama ile korunmalidir.",
    },
    23: {
        "service_category": "Uzak Erisim",
        "risk": "Yuksek",
        "recommendation": "Telnet yerine SSH kullanilmalidir.",
    },
    53: {
        "service_category": "Ad Cozumleme",
        "risk": "Orta",
        "recommendation": "DNS servisi yalnizca gerekli istemcilere acik olmali ve recursive sorgular sinirlandirilmalidir.",
    },
    69: {
        "service_category": "Dosya Aktarimi",
        "risk": "Yuksek",
        "recommendation": "TFTP servisi kimlik dogrulama saglamadigi icin mumkunse kapatilmali veya yalnizca kontrollu segmentlerde kullanilmalidir.",
    },
    80: {
        "service_category": "Web Servisi",
        "risk": "Dusuk",
        "recommendation": "Mumkunse HTTPS kullanimi tercih edilmelidir.",
    },
    123: {
        "service_category": "Zaman Senkronizasyonu",
        "risk": "Dusuk",
        "recommendation": "NTP servisi gereksizse internetten kapatilmali, gerekiyorsa yalnizca guvenilir istemcilere acik olmalidir.",
    },
    135: {
        "service_category": "Sistem Servisi",
        "risk": "Orta",
        "recommendation": "Bu servis gerekmiyorsa ag erisimi sinirlandirilmalidir.",
    },
    139: {
        "service_category": "Dosya Paylasimi",
        "risk": "Yuksek",
        "recommendation": "NetBIOS erisimi gerekmiyorsa kapatilmali veya yerel ag ile sinirlandirilmalidir.",
    },
    161: {
        "service_category": "Ag Yonetimi",
        "risk": "Orta",
        "recommendation": "SNMP icin varsayilan community stringler degistirilmeli ve servis yalnizca yonetim agindan erisilebilir olmalidir.",
    },
    443: {
        "service_category": "Web Servisi",
        "risk": "Dusuk",
        "recommendation": "HTTPS yapilandirmasinin guncel ve guvenli oldugundan emin olunmalidir.",
    },
    445: {
        "service_category": "Dosya Paylasimi",
        "risk": "Yuksek",
        "recommendation": "SMB erisimi firewall ile sinirlandirilmali ve yalnizca gerekli cihazlara acik olmalidir.",
    },
    3389: {
        "service_category": "Uzak Erisim",
        "risk": "Yuksek",
        "recommendation": "RDP erisimi VPN arkasina alinmali ve firewall ile korunmalidir.",
    },
}

VULNERABILITY_RULES = {
    21: [
        {
            "cve_id": "CVE-2011-2523",
            "title": "vsFTPd Backdoor",
            "description": "Eski veya yanlis yapilandirilmis FTP servislerinde uzaktan komut calistirma riski gorulebilir.",
            "match_reason": "FTP servisi tespit edildigi icin bu CVE yerel servis kuralindan onerildi.",
        }
    ],
    22: [
        {
            "cve_id": "CVE-2018-15473",
            "title": "OpenSSH User Enumeration",
            "description": "Bazi OpenSSH surumlerinde kullanici adi dogrulama davranisi bilgi sizdirabilir.",
            "match_reason": "SSH servisi tespit edildigi icin bu CVE yerel servis kuralindan onerildi.",
        }
    ],
    53: [
        {
            "cve_id": "CVE-2020-8616",
            "title": "BIND DNS Query Processing",
            "description": "Bazi DNS sunucularinda sorgu isleme sirasinda hizmet kesintisine yol acabilecek zafiyetler bulunabilir.",
            "match_reason": "DNS servisi tespit edildigi icin bu CVE yerel servis kuralindan onerildi.",
        }
    ],
    69: [
        {
            "cve_id": "CVE-2019-1350",
            "title": "TFTP Service Exposure",
            "description": "Kimlik dogrulamasiz TFTP servisleri dosya erisimi ve yapilandirma sizintisi riski olusturabilir.",
            "match_reason": "TFTP servisi tespit edildigi icin bu CVE yerel servis kuralindan onerildi.",
        }
    ],
    123: [
        {
            "cve_id": "CVE-2015-7704",
            "title": "NTP Amplification Exposure",
            "description": "Acik NTP servisleri yanlis yapilandirildiginda amplification saldirilarina aracilik edebilir.",
            "match_reason": "NTP servisi tespit edildigi icin bu CVE yerel servis kuralindan onerildi.",
        }
    ],
    161: [
        {
            "cve_id": "CVE-2014-2284",
            "title": "SNMP Information Disclosure",
            "description": "Zayif SNMP yapilandirmalari cihaz bilgisi sizintisi ve ag kesfi riskini artirabilir.",
            "match_reason": "SNMP servisi tespit edildigi icin bu CVE yerel servis kuralindan onerildi.",
        }
    ],
    445: [
        {
            "cve_id": "CVE-2017-0144",
            "title": "EternalBlue / SMBv1",
            "description": "SMBv1 kullanan eski Windows sistemlerde uzaktan kod calistirma riski olabilir.",
            "match_reason": "SMB servisi tespit edildigi icin bu CVE yerel servis kuralindan onerildi.",
        }
    ],
    3389: [
        {
            "cve_id": "CVE-2019-0708",
            "title": "BlueKeep / RDP",
            "description": "Eski RDP servislerinde kimlik dogrulama oncesi kritik uzaktan kod calistirma acigi bulunabilir.",
            "match_reason": "RDP servisi tespit edildigi icin bu CVE yerel servis kuralindan onerildi.",
        }
    ],
}

SERVICE_VULNERABILITY_RULES = {
    "ftp": VULNERABILITY_RULES[21],
    "ssh": VULNERABILITY_RULES[22],
    "domain": VULNERABILITY_RULES[53],
    "tftp": VULNERABILITY_RULES[69],
    "ntp": VULNERABILITY_RULES[123],
    "snmp": VULNERABILITY_RULES[161],
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
                "description": "Apache HTTP Server 2.4.49 surumunde dosya yolu gecisi ve bazi yapilandirmalarda uzaktan kod calistirma riski bulunabilir.",
                "severity": "HIGH",
                "source": "Yerel surum kurali",
                "match_reason": "Apache 2.4.49 goruldugu icin bu CVE yerel surum kuralindan onerildi.",
            }
        ],
    },
    {
        "match": lambda port, service_name, service_version: "openssh" in service_version.lower() and "7." in service_version.lower(),
        "cves": [
            {
                "cve_id": "CVE-2018-15473",
                "title": "OpenSSH 7.x User Enumeration",
                "description": "OpenSSH 7.x ailesindeki bazi surumlerde kullanici dogrulama davranisi bilgi sizdirabilir.",
                "severity": "MEDIUM",
                "source": "Yerel surum kurali",
                "match_reason": "OpenSSH 7.x goruldugu icin bu CVE yerel surum kuralindan onerildi.",
            }
        ],
    },
    {
        "match": lambda port, service_name, service_version: port == 445 and "smbv1" in service_version.lower(),
        "cves": [
            {
                "cve_id": "CVE-2017-0144",
                "title": "SMBv1 EternalBlue Exposure",
                "description": "SMBv1 tespiti eski Windows hedeflerde EternalBlue benzeri kritik uzaktan kod calistirma risklerini isaret edebilir.",
                "severity": "CRITICAL",
                "source": "Yerel surum kurali",
                "match_reason": "SMBv1 goruldugu icin bu CVE yerel surum kuralindan onerildi.",
            }
        ],
    },
]

BRUTE_FORCE_PORT_RULES = {
    21: "FTP servisi acik oldugu icin brute-force saldiri riski vardir.",
    22: "SSH servisi acik oldugu icin brute-force saldiri riski vardir.",
    3389: "RDP servisi acik oldugu icin brute-force saldiri riski vardir.",
}


def get_port_info(port_number: int) -> dict:
    return PORT_RULES.get(
        port_number,
        {
            "service_category": "Bilinmiyor",
            "risk": "Bilinmiyor",
            "recommendation": "Bu servis icin manuel guvenlik degerlendirmesi yapilmalidir.",
        },
    )


def calculate_general_risk(high_count: int, medium_count: int, low_count: int) -> str:
    if high_count > 0:
        return "Yuksek"
    if medium_count > 0:
        return "Orta"
    if low_count > 0:
        return "Dusuk"
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
    if risk == "Dusuk":
        return "Orta"
    if risk == "Orta":
        return "Yuksek"
    return risk


def adjust_risk_by_os(port_number: int, risk: str, os_name: str):
    os_family = normalize_os_family(os_name)

    if os_family == "windows" and port_number in {135, 139, 445, 3389}:
        return elevate_risk(risk), "Windows sistemlerde bu port daha yuksek saldiri yuzeyi olusturabilir."
    if os_family == "linux" and port_number in {21, 22}:
        return elevate_risk(risk), "Linux sistemlerde bu servis yanlis yapilandirilirsa uzaktan erisim riski artabilir."
    if os_family == "network" and port_number in {23, 53, 80, 161, 443}:
        return elevate_risk(risk), "Ag cihazlarinda acik yonetim veya servis portlari riski artirabilir."

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
        item.setdefault("source", "Yerel servis kurali")
        item.setdefault(
            "match_reason",
            f"{service_name} servisi tespit edildigi icin bu CVE yerel servis kuralindan onerildi.",
        )
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
    detected = " ".join(parts) if parts else service_name

    return service_name, product or "Bilinmiyor", detected


def _load_xml_root(xml_path=XML_DOSYASI):
    try:
        tree = ET.parse(xml_path)
        return tree.getroot()
    except ET.ParseError:
        pass

    try:
        with open(xml_path, "r", encoding="utf-8", errors="ignore") as file:
            raw_xml = file.read()
    except OSError as error:
        raise ValueError(f"XML dosyasi okunamadi: {error}") from error

    cleaned_xml = raw_xml.lstrip("\ufeff")
    nmaprun_close = "</nmaprun>"

    # Tam kapanış varsa o noktaya kadar kes
    idx = cleaned_xml.rfind(nmaprun_close)
    if idx != -1:
        cleaned_xml = cleaned_xml[: idx + len(nmaprun_close)]
        try:
            return ET.fromstring(cleaned_xml)
        except ET.ParseError:
            pass

    # Nmap zorla durdurulduysa XML yarım kalır; son tam </host> tagına kadar kes
    host_close = "</host>"
    last_host_idx = cleaned_xml.rfind(host_close)
    if last_host_idx != -1:
        truncated = cleaned_xml[: last_host_idx + len(host_close)]
        # nmaprun açılış tagını bul ve kapanışını ekle
        nmaprun_open_end = truncated.find(">")
        if nmaprun_open_end != -1:
            candidate = truncated.rstrip() + nmaprun_close
            try:
                return ET.fromstring(candidate)
            except ET.ParseError:
                pass

    # Son çare: nmaprun başlığını bul, boş bir nmaprun döndür
    nmaprun_start = cleaned_xml.find("<nmaprun")
    if nmaprun_start != -1:
        header_end = cleaned_xml.find(">", nmaprun_start)
        if header_end != -1:
            empty_doc = cleaned_xml[nmaprun_start: header_end + 1] + nmaprun_close
            try:
                return ET.fromstring(empty_doc)
            except ET.ParseError:
                pass

    raise ValueError("Nmap XML cikti dosyasi bozuk veya eksik. Tarama yeniden calistirilmali.")


def summarize_nse_output(script_id, output):
    clean_output = " ".join((output or "").split())
    lowered = clean_output.lower()

    if script_id == "ftp-anon":
        if "anonymous ftp login allowed" in lowered:
            return "Anonymous FTP acik"
        return "FTP anonymous erisim bilgisi bulundu"

    if script_id == "http-title":
        return f"HTTP title: {clean_output}" if clean_output else "HTTP title bilgisi bulundu"

    if script_id == "http-headers":
        return "HTTP header bilgileri toplandi"

    if script_id == "smb-protocols":
        if "smbv1" in lowered:
            return "SMBv1 acik"
        return "SMB protokol bilgisi bulundu"

    if script_id == "smb-security-mode":
        if "message_signing: disabled" in lowered:
            return "SMB signing kapali olabilir"
        return "SMB guvenlik modu bilgisi bulundu"

    if script_id == "vulners" or script_id == "vuln":
        return "CVE veya zafiyet kontrol ciktisi bulundu"

    if clean_output:
        return clean_output[:160]
    return f"{script_id} script bulgusu bulundu"


def collect_nse_findings(port):
    findings = []

    for script in port.findall("script"):
        script_id = script.get("id", "Bilinmeyen script")
        output = script.get("output", "")
        findings.append(
            {
                "id": script_id,
                "output": output,
                "summary": summarize_nse_output(script_id, output),
            }
        )

    return findings


def explain_port_state(port_state):
    explanations = {
        "open": "Bu port aktif ve baglanti kabul ediyor.",
        "filtered": "Firewall veya benzeri bir ag filtresi bu porta erisimi engelliyor olabilir.",
        "closed": "Bu port kapali; servis su anda baglanti kabul etmiyor.",
    }
    return explanations.get(port_state, "Port durumu algilandi ancak ek aciklama bulunamadi.")


def parse_results(xml_path=XML_DOSYASI):
    root = _load_xml_root(xml_path)

    all_hosts_summary = []
    host_reports = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        address = host.find("address")
        ip = address.get("addr") if address is not None else "Bilinmiyor"
        detected_os = detect_os(host)
        scan_timed_out = host.get("timedout") == "true"

        total_open_ports = 0
        total_filtered_ports = 0
        high_risk_count = 0
        medium_risk_count = 0
        low_risk_count = 0
        known_cve_count = 0
        brute_force_risk_count = 0
        nse_finding_count = 0
        open_ports_data = []
        all_ports_data = []

        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                state = port.find("state")
                service = port.find("service")

                if state is None:
                    continue

                port_id = int(port.get("portid"))
                protocol = port.get("protocol")
                service_name, service_product, detected_version = build_service_version(service)
                port_state = state.get("state")
                state_explanation = explain_port_state(port_state)

                if port_state == "filtered":
                    total_filtered_ports += 1
                elif port_state not in {"open", "closed"}:
                    continue

                all_port_entry = {
                    "port": port_id,
                    "protocol": protocol,
                    "state": port_state,
                    "state_explanation": state_explanation,
                    "service": service_name,
                    "service_product": service_product,
                    "service_version": detected_version,
                    "category": "-",
                    "risk": "-",
                    "base_risk": "-",
                    "os_risk_note": "-",
                    "brute_force_note": "-",
                    "has_brute_force_risk": False,
                    "recommendation": state_explanation,
                    "cves": [],
                    "nse_findings": [],
                }
                all_ports_data.append(all_port_entry)

                if port_state != "open":
                    continue

                port_info = get_port_info(port_id)
                risk = port_info["risk"]
                adjusted_risk, os_risk_note = adjust_risk_by_os(port_id, risk, detected_os)
                known_cves = get_known_cves(port_id, service_name, detected_version)
                brute_force_note = get_bruteforce_risk_note(port_id)
                has_brute_force_risk = port_id in BRUTE_FORCE_PORT_RULES
                nse_findings = collect_nse_findings(port)

                total_open_ports += 1
                known_cve_count += len(known_cves)
                nse_finding_count += len(nse_findings)
                if has_brute_force_risk:
                    brute_force_risk_count += 1

                if adjusted_risk == "Yuksek":
                    high_risk_count += 1
                elif adjusted_risk == "Orta":
                    medium_risk_count += 1
                elif adjusted_risk == "Dusuk":
                    low_risk_count += 1

                open_port_entry = {
                    "port": port_id,
                    "protocol": protocol,
                    "state": port_state,
                    "state_explanation": state_explanation,
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
                    "nse_findings": nse_findings,
                }
                open_ports_data.append(open_port_entry)
                all_ports_data[-1] = open_port_entry

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
                "nse_finding_count": nse_finding_count,
                "scan_timed_out": scan_timed_out,
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
                "nse_finding_count": nse_finding_count,
                "general_risk": general_risk,
                "host_score": host_score,
                "open_ports_data": open_ports_data,
                "all_ports_data": all_ports_data,
                "scan_timed_out": scan_timed_out,
            }
        )

    total_hosts = len(all_hosts_summary)
    high_risk_hosts = sum(1 for host in all_hosts_summary if host["general_risk"] == "Yuksek")
    medium_risk_hosts = sum(1 for host in all_hosts_summary if host["general_risk"] == "Orta")
    low_risk_hosts = sum(1 for host in all_hosts_summary if host["general_risk"] == "Dusuk")
    hosts_with_known_cves = sum(1 for host in all_hosts_summary if host["known_cve_count"] > 0)
    hosts_with_nse_findings = sum(1 for host in all_hosts_summary if host["nse_finding_count"] > 0)
    timed_out_hosts = sum(1 for host in all_hosts_summary if host.get("scan_timed_out"))
    total_known_cves = sum(host["known_cve_count"] for host in all_hosts_summary)
    total_nse_findings = sum(host["nse_finding_count"] for host in all_hosts_summary)
    firewall_detected_hosts = sum(1 for host in all_hosts_summary if host["firewall_detected"])
    total_filtered_ports = sum(host["filtered_ports"] for host in all_hosts_summary)
    brute_force_risk_hosts = sum(1 for host in all_hosts_summary if host["brute_force_risk_count"] > 0)

    most_risky_host = "Yok"
    if all_hosts_summary:
        risky = max(all_hosts_summary, key=lambda host: host["score"])
        most_risky_host = f"{risky['ip']} (Skor: {risky['score']}, Acik Port: {risky['open_ports']})"

    network_summary = {
        "total_hosts": total_hosts,
        "high_risk_hosts": high_risk_hosts,
        "medium_risk_hosts": medium_risk_hosts,
        "low_risk_hosts": low_risk_hosts,
        "hosts_with_known_cves": hosts_with_known_cves,
        "hosts_with_nse_findings": hosts_with_nse_findings,
        "timed_out_hosts": timed_out_hosts,
        "total_known_cves": total_known_cves,
        "total_nse_findings": total_nse_findings,
        "firewall_detected_hosts": firewall_detected_hosts,
        "total_filtered_ports": total_filtered_ports,
        "brute_force_risk_hosts": brute_force_risk_hosts,
        "most_risky_host": most_risky_host,
        "host_list": all_hosts_summary,
    }

    return network_summary, host_reports
