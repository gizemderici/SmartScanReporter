import os
import re
import socket
import subprocess
import xml.etree.ElementTree as ET
from ipaddress import ip_network


BASE_DIR = os.path.dirname(__file__)
XML_DOSYASI = os.path.join(BASE_DIR, "scan_results", "output.xml")
DISCOVERY_XML_DOSYASI = os.path.join(BASE_DIR, "scan_results", "discovery_output.xml")
NMAP_MAC_PREFIX_CANDIDATES = [
    os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Nmap", "nmap-mac-prefixes"),
    os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Nmap", "nmap-mac-prefixes"),
]
_MAC_VENDOR_CACHE = None
_HOSTNAME_CACHE = {}
MAX_DISCOVERY_REVERSE_DNS_LOOKUPS = 64
SCAN_PROFILES = {
    "quick": {
        "label": "Hizli Tarama",
        "args": [],
    },
    "syn": {
        "label": "SYN Tarama",
        "args": ["-sS"],
    },
    "udp": {
        "label": "UDP Tarama",
        "args": ["-sU"],
    },
    "detailed": {
        "label": "Detayli Tarama",
        "args": ["-sV", "-O"],
    },
    "ping": {
        "label": "Ping Scan",
        "args": ["-sn"],
    },
    "vuln": {
        "label": "Zafiyet Taramasi",
        "args": ["-sV", "--script", "vuln"],
    },
}
NSE_SCRIPT_OPTIONS = {
    "safe": {
        "label": "Guvenli Scriptler",
        "scripts": ["default"],
    },
    "http": {
        "label": "HTTP Bilgi Toplama",
        "scripts": ["http-title", "http-headers"],
    },
    "smb": {
        "label": "SMB Kontrol",
        "scripts": ["smb-protocols", "smb-security-mode"],
    },
    "cve": {
        "label": "CVE Kontrol",
        "scripts": ["vuln"],
    },
}
PORT_SCOPE_OPTIONS = {
    "default": "Varsayilan Portlar",
    "custom": "Ozel Port Araligi",
    "all": "Tum Portlar",
}


def get_scan_profile(scan_type: str):
    return SCAN_PROFILES.get(scan_type, SCAN_PROFILES["detailed"])


def get_scan_label(scan_type: str) -> str:
    return get_scan_profile(scan_type)["label"]


def normalize_port_scope(port_scope):
    scope = (port_scope or "default").strip().lower()
    return scope if scope in PORT_SCOPE_OPTIONS else "default"


def normalize_port_spec(port_scope, port_spec=""):
    scope = normalize_port_scope(port_scope)
    if scope != "custom":
        return ""

    value = "".join((port_spec or "").strip().split())
    if not value:
        raise ValueError("Ozel port araligi secildiginde port bilgisi girilmelidir.")

    for part in value.split(","):
        if not re.fullmatch(r"\d+(-\d+)?", part or ""):
            raise ValueError("Port formati gecersiz. Ornek: 22,80,443 veya 1-1000")
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start_port = int(start_text)
            end_port = int(end_text)
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                raise ValueError("Port araligi 1-65535 arasynda olmali ve baslangic bitisten buyuk olmamalidir.")
        else:
            port = int(part)
            if port < 1 or port > 65535:
                raise ValueError("Port numaralari 1 ile 65535 arasynda olmalidir.")

    return value


def get_port_label(port_scope, port_spec=""):
    scope = normalize_port_scope(port_scope)
    if scope == "all":
        return "Tum Portlar"
    if scope == "custom":
        return f"Portlar: {normalize_port_spec(scope, port_spec)}"
    return "Varsayilan Portlar"


def normalize_nse_scripts(selected_scripts=None):
    normalized = []
    for key in selected_scripts or []:
        script_key = (key or "").strip().lower()
        if script_key in NSE_SCRIPT_OPTIONS and script_key not in normalized:
            normalized.append(script_key)
    return normalized


def get_nse_script_labels(selected_scripts=None):
    normalized = normalize_nse_scripts(selected_scripts)
    return [NSE_SCRIPT_OPTIONS[key]["label"] for key in normalized]


def build_nse_args(selected_scripts=None):
    normalized = normalize_nse_scripts(selected_scripts)
    script_names = []
    for key in normalized:
        for script_name in NSE_SCRIPT_OPTIONS[key]["scripts"]:
            if script_name not in script_names:
                script_names.append(script_name)
    if not script_names:
        return []
    return ["--script", ",".join(script_names)]


def build_port_args(port_scope="default", port_spec=""):
    scope = normalize_port_scope(port_scope)
    if scope == "all":
        return ["-p-"]
    if scope == "custom":
        return ["-p", normalize_port_spec(scope, port_spec)]
    return []


def is_subnet_target(target) -> bool:
    value = (target or "").strip() if isinstance(target, str) else ""
    if not value or "/" not in value:
        return False
    try:
        ip_network(value, strict=False)
    except ValueError:
        return False
    return True


def validate_target_value(target_value: str) -> str:
    value = str(target_value or "").strip()
    if not value:
        raise ValueError("Hedef bos birakilamaz.")
    if value.startswith("-"):
        raise ValueError("Hedef degeri '-' ile baslayamaz.")
    if any(ch.isspace() for ch in value):
        raise ValueError("Hedef degeri bosluk iceremez.")
    return value


def normalize_targets(target):
    if isinstance(target, (list, tuple, set)):
        return [validate_target_value(item) for item in target if str(item).strip()]
    value = validate_target_value(target) if str(target or "").strip() else ""
    return [value] if value else []


def build_nmap_command(
    target,
    scan_type: str = "detailed",
    selected_scripts=None,
    port_scope="default",
    port_spec="",
    output_xml_path=XML_DOSYASI,
):
    profile = get_scan_profile(scan_type)
    nse_args = build_nse_args(selected_scripts)
    port_args = build_port_args(port_scope, port_spec)
    targets = normalize_targets(target)

    # Buyuk aglar ve coklu host taramalari icin daha dengeli ayarlar
    subnet_or_multi_host = len(targets) > 1 or any(is_subnet_target(item) for item in targets)
    if subnet_or_multi_host:
        host_group = "4"
        max_parallelism = "4"
        max_retries = "2"
        min_rate = "20"
        host_timeout = "240s" if (nse_args or scan_type in {"detailed", "vuln"}) else "120s"
    else:
        host_group = "8"
        max_parallelism = "8"
        max_retries = "1"
        min_rate = "50"
        host_timeout = "180s" if (nse_args or scan_type in {"detailed", "vuln"}) else "90s"
    performance_args = [
        "--max-hostgroup", host_group,
        "--host-timeout", host_timeout,
        "--max-parallelism", max_parallelism,
        "--max-retries", max_retries,
        "--min-rate", min_rate,
    ]

    return ["nmap", *profile["args"], *port_args, *nse_args, *performance_args, "-oX", output_xml_path, "--", *targets]


def build_discovery_command(target: str, output_xml_path=DISCOVERY_XML_DOSYASI):
    target = validate_target_value(target)
    return [
        "nmap",
        "-sn",
        "-PR",
        "--max-retries", "1",
        "--min-parallelism", "16",
        "--max-rtt-timeout", "750ms",
        "--host-timeout", "8s",
        "-oX",
        output_xml_path,
        "--",
        target,
    ]


def start_nmap_scan(
    target,
    scan_type: str = "detailed",
    selected_scripts=None,
    port_scope="default",
    port_spec="",
    output_xml_path=XML_DOSYASI,
):
    os.makedirs(os.path.dirname(output_xml_path), exist_ok=True)
    if os.path.exists(output_xml_path):
        os.remove(output_xml_path)
    command = build_nmap_command(target, scan_type, selected_scripts, port_scope, port_spec, output_xml_path)
    return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def run_nmap_scan(
    target: str,
    scan_type: str = "detailed",
    selected_scripts=None,
    port_scope="default",
    port_spec="",
    output_xml_path=XML_DOSYASI,
):
    process = start_nmap_scan(target, scan_type, selected_scripts, port_scope, port_spec, output_xml_path)
    _, stderr = process.communicate()
    return process.returncode == 0, stderr


def run_ping_discovery(target: str, output_xml_path=DISCOVERY_XML_DOSYASI):
    os.makedirs(os.path.dirname(output_xml_path), exist_ok=True)
    if os.path.exists(output_xml_path):
        os.remove(output_xml_path)
    command = build_discovery_command(target, output_xml_path)
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode == 0, result.stderr


def start_ping_discovery(target: str, output_xml_path=DISCOVERY_XML_DOSYASI):
    os.makedirs(os.path.dirname(output_xml_path), exist_ok=True)
    if os.path.exists(output_xml_path):
        os.remove(output_xml_path)
    command = build_discovery_command(target, output_xml_path)
    return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def _normalize_mac_prefix(mac_address):
    value = "".join(ch for ch in (mac_address or "").upper() if ch in "0123456789ABCDEF")
    return value[:6] if len(value) >= 6 else ""


def _load_mac_vendor_map():
    global _MAC_VENDOR_CACHE
    if _MAC_VENDOR_CACHE is not None:
        return _MAC_VENDOR_CACHE

    vendor_map = {}
    for path in NMAP_MAC_PREFIX_CANDIDATES:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                for line in handle:
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    parts = stripped.split(None, 1)
                    if len(parts) != 2:
                        continue
                    prefix = _normalize_mac_prefix(parts[0])
                    if prefix and prefix not in vendor_map:
                        vendor_map[prefix] = parts[1].strip()
        except OSError:
            continue
        if vendor_map:
            break

    _MAC_VENDOR_CACHE = vendor_map
    return _MAC_VENDOR_CACHE


def lookup_vendor_by_mac(mac_address):
    prefix = _normalize_mac_prefix(mac_address)
    if not prefix:
        return None
    return _load_mac_vendor_map().get(prefix)


def resolve_hostname(ip_address):
    if not ip_address or ip_address == "Bilinmiyor":
        return None
    if ip_address in _HOSTNAME_CACHE:
        return _HOSTNAME_CACHE[ip_address]
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
    except (socket.herror, socket.gaierror, OSError):
        _HOSTNAME_CACHE[ip_address] = None
        return None
    normalized = (hostname or "").strip().rstrip(".")
    _HOSTNAME_CACHE[ip_address] = normalized or None
    return _HOSTNAME_CACHE[ip_address]


def parse_discovery_results(xml_path: str = DISCOVERY_XML_DOSYASI, resolve_missing_hostnames=True):
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError) as error:
        raise ValueError(f"Discovery XML okunamadi: {error}") from error

    raw_devices = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip_address = "Bilinmiyor"
        mac_address = None
        vendor = None

        for address in host.findall("address"):
            addr_type = address.get("addrtype")
            if addr_type == "ipv4":
                ip_address = address.get("addr", "Bilinmiyor")
            elif addr_type == "mac":
                mac_address = address.get("addr")
                vendor = address.get("vendor")

        hostnames = host.find("hostnames")
        hostname = None
        if hostnames is not None:
            hostname_node = hostnames.find("hostname")
            if hostname_node is not None:
                hostname = hostname_node.get("name")
        raw_devices.append(
            {
                "ip": ip_address,
                "hostname": hostname,
                "mac": mac_address or "Bilinmiyor",
                "vendor": vendor,
            }
        )

    unresolved_hostname_budget = MAX_DISCOVERY_REVERSE_DNS_LOOKUPS if resolve_missing_hostnames else 0
    devices = []
    for device in raw_devices:
        hostname = device.get("hostname")
        vendor = device.get("vendor")
        mac_address = device.get("mac")
        ip_address = device.get("ip")

        if not hostname and unresolved_hostname_budget > 0:
            hostname = resolve_hostname(ip_address)
            unresolved_hostname_budget -= 1
        if not vendor and mac_address and mac_address != "Bilinmiyor":
            vendor = lookup_vendor_by_mac(mac_address)

        devices.append(
            {
                "ip": ip_address,
                "hostname": hostname or "Bilinmiyor",
                "mac": mac_address or "Bilinmiyor",
                "vendor": vendor or "Bilinmiyor",
            }
        )

    return {
        "target": target_from_xml(root),
        "device_count": len(devices),
        "devices": devices,
    }


def target_from_xml(root):
    runstats = root.find("runstats")
    if runstats is None:
        return "Bilinmiyor"
    finished = runstats.find("finished")
    if finished is None:
        return "Bilinmiyor"
    return finished.get("summary", "Bilinmiyor")
