import os
import re
import shutil
import threading
import time
import uuid
import warnings
from ipaddress import ip_network

os.environ["MPLBACKEND"] = "Agg"

# Matplotlib uyarilarini kapat
import matplotlib

matplotlib.use("Agg", force=True)
matplotlib.rcParams["figure.max_open_warning"] = 0
warnings.filterwarnings("ignore", message=".*Matplotlib.*")
warnings.filterwarnings("ignore", message=".*GUI.*")

from flask import Flask, Response, jsonify, render_template, request, send_file, url_for

from analyzer import parse_results
from chart_generator import generate_discovery_topology, generate_network_topology, generate_os_chart, generate_risk_chart
from cve_lookup import enrich_reports_with_online_cves
from env_loader import load_env_file
from history import (
    build_history_compare_data,
    get_history_compare_candidates,
    get_recent_scan_history,
    get_scan_history_archive,
    get_scan_history_detail,
    init_history_db,
    record_scan_history,
)
from history_tracker import record_and_compare_discovery, record_and_compare_scan
from reporter import (
    HTML_RAPOR_DOSYASI,
    PDF_RAPOR_DOSYASI,
    TXT_RAPOR_DOSYASI,
    build_printable_report_html,
    can_generate_pdf,
    generate_reports,
)
from scenario_generator import generate_attack_scenarios
from scanner import (
    NSE_SCRIPT_OPTIONS,
    PORT_SCOPE_OPTIONS,
    SCAN_PROFILES,
    XML_DOSYASI,
    get_nse_script_labels,
    is_subnet_target,
    get_port_label,
    get_scan_label,
    normalize_nse_scripts,
    normalize_port_scope,
    normalize_port_spec,
    parse_discovery_results,
    run_nmap_scan,
    run_ping_discovery,
    start_nmap_scan,
    start_ping_discovery,
    validate_target_value,
)
from team_advisor import BLUE_TEAM, RED_TEAM, apply_team_mode_analysis


load_env_file()

app = Flask(__name__)
init_history_db()
SCAN_JOBS = {}
SCAN_JOBS_LOCK = threading.Lock()
RUNS_DIR = os.path.join(app.root_path, "job_runs")


def _response_not_found(message):
    return Response(message, status=404, mimetype="text/plain; charset=utf-8")


def _job_workspace(job_id):
    base_dir = os.path.join(RUNS_DIR, job_id)
    return {
        "base_dir": base_dir,
        "reports_dir": os.path.join(base_dir, "reports"),
        "charts_dir": os.path.join(base_dir, "charts"),
        "html_report_path": os.path.join(base_dir, "reports", "report.html"),
        "txt_report_path": os.path.join(base_dir, "reports", "report.txt"),
        "pdf_report_path": os.path.join(base_dir, "reports", "report.pdf"),
        "risk_chart_path": os.path.join(base_dir, "charts", "risk_chart.png"),
        "os_chart_path": os.path.join(base_dir, "charts", "os_distribution.png"),
        "topology_chart_path": os.path.join(base_dir, "charts", "network_topology.png"),
        "discovery_topology_path": os.path.join(base_dir, "charts", "discovery_topology.png"),
        "xml_path": os.path.join(base_dir, "output.xml"),
        "discovery_xml_path": os.path.join(base_dir, "discovery_output.xml"),
    }


def _job_artifact_url(job_id, artifact_name):
    return f"/job-artifact/{job_id}/{artifact_name}"


def _archive_job_outputs(job_id):
    job = _get_job(job_id)
    if job is None:
        return

    workspace = job.get("workspace") or _job_workspace(job_id)
    os.makedirs(workspace["reports_dir"], exist_ok=True)
    os.makedirs(workspace["charts_dir"], exist_ok=True)

    copies = [
        (HTML_RAPOR_DOSYASI, workspace["html_report_path"]),
        (TXT_RAPOR_DOSYASI, workspace["txt_report_path"]),
        (PDF_RAPOR_DOSYASI, workspace["pdf_report_path"]),
        (os.path.join(app.root_path, "static", "risk_chart.png"), workspace["risk_chart_path"]),
        (os.path.join(app.root_path, "static", "os_distribution.png"), workspace["os_chart_path"]),
        (os.path.join(app.root_path, "static", "network_topology.png"), workspace["topology_chart_path"]),
    ]
    for source, target in copies:
        if os.path.exists(source):
            shutil.copy2(source, target)

    if os.path.exists(workspace["html_report_path"]):
        with open(workspace["html_report_path"], "r", encoding="utf-8", errors="ignore") as handle:
            html = handle.read()
        html = html.replace("/static/risk_chart.png", _job_artifact_url(job_id, "risk_chart.png"))
        html = html.replace("/static/os_distribution.png", _job_artifact_url(job_id, "os_distribution.png"))
        html = html.replace("/static/network_topology.png", _job_artifact_url(job_id, "network_topology.png"))
        html = html.replace('class="unknown">Yuksek', 'class="high">Yuksek')
        html = html.replace('class="unknown">Orta', 'class="medium">Orta')
        html = html.replace('class="unknown">Dusuk', 'class="low">Dusuk')
        with open(workspace["html_report_path"], "w", encoding="utf-8") as handle:
            handle.write(html)


def _safe_file_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def _safe_file_mtime(path):
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(path)))
    except OSError:
        return None


def _format_file_size(num_bytes):
    if num_bytes is None:
        return "Hazir degil"
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    return f"{num_bytes / (1024 * 1024):.2f} MB"


def _build_export_previews(report_html_url, report_pdf_url, report_txt_url, workspace=None):
    html_path = HTML_RAPOR_DOSYASI
    pdf_path = PDF_RAPOR_DOSYASI
    txt_path = TXT_RAPOR_DOSYASI
    if workspace:
        html_path = workspace.get("html_report_path", html_path)
        pdf_path = workspace.get("pdf_report_path", pdf_path)
        txt_path = workspace.get("txt_report_path", txt_path)

    items = [
        {
            "label": "HTML",
            "path": html_path,
            "url": report_html_url,
            "summary": "Tum dashboard ozetleri, host kartlari ve gorseller.",
        },
        {
            "label": "PDF",
            "path": pdf_path if can_generate_pdf() else html_path,
            "url": report_pdf_url,
            "summary": "Yonetim paylasimi ve yazdirilabilir resmi rapor cikisi.",
        },
        {
            "label": "TXT",
            "path": txt_path,
            "url": report_txt_url,
            "summary": "Teknik metin ozet, port ve CVE listeleri.",
        },
    ]

    previews = []
    for item in items:
        exists = os.path.exists(item["path"])
        previews.append(
            {
                "label": item["label"],
                "url": item["url"],
                "summary": item["summary"],
                "available": exists,
                "size_label": _format_file_size(_safe_file_size(item["path"]) if exists else None),
                "updated_at": _safe_file_mtime(item["path"]) if exists else "Hazir degil",
            }
        )
    return previews


def _has_active_scan():
    with SCAN_JOBS_LOCK:
        return any(job.get("status") in {"queued", "running"} for job in SCAN_JOBS.values())


def _append_job_log(job, level, message):
    logs = job.setdefault("logs", [])
    logs.append({"level": level, "message": message})
    if len(logs) > 20:
        del logs[:-20]


def _attach_udp_summary(network_summary, host_reports):
    udp_services = []
    udp_host_ips = set()

    for host in host_reports:
        for port in host.get("open_ports_data", []):
            if (port.get("protocol") or "").lower() != "udp":
                continue
            udp_host_ips.add(host.get("ip"))
            udp_services.append(
                {
                    "ip": host.get("ip", "Bilinmiyor"),
                    "port": port.get("port"),
                    "service": port.get("service", "Bilinmiyor"),
                    "risk": port.get("risk", "Bilinmiyor"),
                }
            )

    network_summary["udp_service_count"] = len(udp_services)
    network_summary["udp_host_count"] = len(udp_host_ips)
    network_summary["udp_services"] = udp_services[:8]


def _attach_nse_summary(network_summary, host_reports):
    findings = []
    host_ips = set()

    for host in host_reports:
        for port in host.get("open_ports_data", []):
            for finding in port.get("nse_findings", []):
                host_ips.add(host.get("ip"))
                findings.append(
                    {
                        "ip": host.get("ip", "Bilinmiyor"),
                        "port": port.get("port"),
                        "protocol": port.get("protocol", "tcp"),
                        "service": port.get("service", "Bilinmiyor"),
                        "script_id": finding.get("id", "Bilinmeyen script"),
                        "summary": finding.get("summary", "Script bulgusu bulundu"),
                    }
                )

    network_summary["nse_finding_count"] = len(findings)
    network_summary["nse_host_count"] = len(host_ips)
    network_summary["nse_findings"] = findings[:10]


def _build_network_summary_from_hosts(host_reports):
    host_list = []
    for host in host_reports:
        host_list.append(
            {
                "ip": host.get("ip", "Bilinmiyor"),
                "detected_os": host.get("detected_os", "Bilinmiyor"),
                "general_risk": host.get("general_risk", "Bilinmiyor"),
                "score": host.get("host_score", 0),
                "open_ports": host.get("total_open_ports", 0),
                "filtered_ports": host.get("total_filtered_ports", 0),
                "firewall_detected": bool(host.get("firewall_detected")),
                "brute_force_risk_count": host.get("brute_force_risk_count", 0),
                "known_cve_count": host.get("known_cve_count", 0),
                "nse_finding_count": host.get("nse_finding_count", 0),
                "scan_timed_out": bool(host.get("scan_timed_out")),
            }
        )

    total_hosts = len(host_list)
    high_risk_hosts = sum(1 for host in host_list if host["general_risk"] == "Yuksek")
    medium_risk_hosts = sum(1 for host in host_list if host["general_risk"] == "Orta")
    low_risk_hosts = sum(1 for host in host_list if host["general_risk"] == "Dusuk")
    hosts_with_known_cves = sum(1 for host in host_list if host["known_cve_count"] > 0)
    hosts_with_nse_findings = sum(1 for host in host_list if host["nse_finding_count"] > 0)
    timed_out_hosts = sum(1 for host in host_list if host["scan_timed_out"])
    total_known_cves = sum(host["known_cve_count"] for host in host_list)
    total_nse_findings = sum(host["nse_finding_count"] for host in host_list)
    firewall_detected_hosts = sum(1 for host in host_list if host["firewall_detected"])
    total_filtered_ports = sum(host["filtered_ports"] for host in host_list)
    brute_force_risk_hosts = sum(1 for host in host_list if host["brute_force_risk_count"] > 0)

    most_risky_host = "Yok"
    if host_list:
        risky = max(host_list, key=lambda host: host["score"])
        most_risky_host = f"{risky['ip']} (Skor: {risky['score']}, Acik Port: {risky['open_ports']})"

    return {
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
        "host_list": host_list,
    }


def _retryable_timed_out_hosts(host_reports):
    retryable = []
    for host in host_reports:
        if host.get("scan_timed_out") and host.get("total_open_ports", 0) == 0 and host.get("ip"):
            retryable.append(host["ip"])
    return retryable


def _retry_timed_out_hosts(job_id, host_reports, port_scope, port_spec):
    retryable_ips = _retryable_timed_out_hosts(host_reports)
    if not retryable_ips:
        return _build_network_summary_from_hosts(host_reports), host_reports, 0

    updated_hosts = list(host_reports)
    refreshed_count = 0

    for index, ip_address in enumerate(retryable_ips, start=1):
        retry_xml_path = os.path.join(_job_workspace(job_id)["base_dir"], f"retry_{index}.xml")
        _update_job(
            job_id,
            progress=min(44, 32 + index),
            message=f"Zaman asimina ugrayan {ip_address} icin hafif yeniden tarama yapiliyor.",
            current_step="nmap",
            log_message=f"{ip_address} icin tek host quick yeniden tarama baslatildi.",
            log_level="warn",
        )

        success, _ = run_nmap_scan(
            ip_address,
            scan_type="quick",
            selected_scripts=[],
            port_scope=port_scope,
            port_spec=port_spec,
            output_xml_path=retry_xml_path,
        )
        if not success:
            continue

        try:
            _, retry_hosts = parse_results(retry_xml_path)
        except ValueError:
            continue

        if not retry_hosts:
            continue

        retry_host = retry_hosts[0]
        if retry_host.get("total_open_ports", 0) == 0 and retry_host.get("scan_timed_out"):
            continue

        for host_index, existing_host in enumerate(updated_hosts):
            if existing_host.get("ip") == ip_address:
                updated_hosts[host_index] = retry_host
                refreshed_count += 1
                break

    return _build_network_summary_from_hosts(updated_hosts), updated_hosts, refreshed_count


def _create_job(target, team_mode, scan_type, nse_scripts, port_scope, port_spec):
    job_id = uuid.uuid4().hex
    workspace = _job_workspace(job_id)
    os.makedirs(workspace["base_dir"], exist_ok=True)
    nse_script_labels = get_nse_script_labels(nse_scripts)
    port_label = get_port_label(port_scope, port_spec)
    job = {
        "id": job_id,
        "target": target,
        "team_mode": team_mode,
        "scan_type": scan_type,
        "scan_label": get_scan_label(scan_type),
        "port_scope": port_scope,
        "port_spec": port_spec,
        "port_label": port_label,
        "nse_scripts": nse_scripts,
        "nse_script_labels": nse_script_labels,
        "status": "queued",
        "progress": 0,
        "message": "Tarama sirasina alindi.",
        "error": None,
        "result": None,
        "cancel_requested": False,
        "process": None,
        "current_step": "queued",
        "logs": [],
        "workspace": workspace,
        "chart_urls": {
            "risk": _job_artifact_url(job_id, "risk_chart.png"),
            "os": _job_artifact_url(job_id, "os_distribution.png"),
            "topology": _job_artifact_url(job_id, "network_topology.png"),
        },
        "report_urls": {
            "html": f"/report?job={job_id}",
            "txt": f"/report/txt?job={job_id}",
            "pdf": f"/report/pdf?job={job_id}",
        },
    }
    _append_job_log(job, "info", f"Tarama sirasina alindi. Mod: {get_scan_label(scan_type)}")
    _append_job_log(job, "info", f"Port kapsami: {port_label}")
    if nse_script_labels:
        _append_job_log(job, "info", f"NSE script secimleri: {', '.join(nse_script_labels)}")
    with SCAN_JOBS_LOCK:
        SCAN_JOBS[job_id] = job
    return job


def _update_job(job_id, **fields):
    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(job_id)
        if job is not None:
            log_message = fields.pop("log_message", None)
            log_level = fields.pop("log_level", "info")
            job.update(fields)
            if log_message:
                _append_job_log(job, log_level, log_message)


def _get_job(job_id):
    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(job_id)
        if job is None:
            return None
        return dict(job)


def _mark_job_canceled(job_id, progress=None, message="Tarama iptal edildi."):
    fields = {
        "status": "canceled",
        "message": message,
        "error": None,
        "process": None,
        "log_message": message,
        "log_level": "warn",
    }
    if progress is not None:
        fields["progress"] = progress
    _update_job(job_id, **fields)


def _job_cancel_requested(job_id):
    job = _get_job(job_id)
    return bool(job and job.get("cancel_requested"))


def _stop_job_process(job_id):
    job = _get_job(job_id)
    process = None if job is None else job.get("process")
    if process is None:
        return

    try:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except Exception:
                process.kill()
    except Exception:
        pass
    finally:
        _update_job(job_id, process=None)


def _check_for_cancel(job_id, progress, message):
    if _job_cancel_requested(job_id):
        _mark_job_canceled(job_id, progress=progress, message=message)
        return True
    return False


def _estimate_target_size(target):
    if isinstance(target, (list, tuple, set)):
        return max(1, len(target))
    value = (target or "").strip()
    if not value:
        return 1
    try:
        if "/" in value:
            return max(1, int(ip_network(value, strict=False).num_addresses))
    except ValueError:
        return 1
    return 1


def _filter_active_hosts_for_target(target, active_hosts):
    if not isinstance(active_hosts, list):
        return []

    try:
        subnet = ip_network((target or "").strip(), strict=False)
    except ValueError:
        return [host for host in active_hosts if host]

    valid_hosts = {str(host) for host in subnet.hosts()}
    filtered = []
    for host in active_hosts:
        if host in valid_hosts and host not in filtered:
            filtered.append(host)
    return filtered


def _extract_hosts_from_partial_discovery_xml(xml_path, target):
    try:
        with open(xml_path, "r", encoding="utf-8", errors="ignore") as handle:
            xml_text = handle.read()
    except OSError:
        return []

    host_matches = re.findall(
        r'<host>\s*<status[^>]*state="up"[^>]*>.*?<address[^>]*addr="([0-9.]+)"[^>]*addrtype="ipv4"',
        xml_text,
        flags=re.DOTALL,
    )
    return _filter_active_hosts_for_target(target, host_matches)


def _load_discovery_hosts_best_effort(xml_path, target):
    try:
        discovery_result = parse_discovery_results(xml_path)
    except ValueError:
        return _extract_hosts_from_partial_discovery_xml(xml_path, target)

    active_hosts = [
        device.get("ip")
        for device in discovery_result.get("devices", [])
        if device.get("ip") and device.get("ip") != "Bilinmiyor"
    ]
    return _filter_active_hosts_for_target(target, active_hosts)


def _run_discovery_phase(job_id, target):
    job = _get_job(job_id)
    workspace = (job or {}).get("workspace") or _job_workspace(job_id)
    _update_job(
        job_id,
        progress=8,
        message="Subnet icindeki canli hostlar kesfediliyor.",
        current_step="nmap",
        log_message="Subnet hedefi algilandi, once canli host kesfi baslatildi.",
    )
    process = start_ping_discovery(target, output_xml_path=workspace["discovery_xml_path"])
    _update_job(job_id, process=process)

    discovery_started_at = time.time()
    last_live_update = 0
    target_size = _estimate_target_size(target)
    if target_size <= 32:
        max_discovery_seconds = 90
    elif target_size <= 256:
        max_discovery_seconds = 180
    else:
        max_discovery_seconds = 300
    discovery_timed_out = False

    while process.poll() is None:
        if _job_cancel_requested(job_id):
            _stop_job_process(job_id)
            _mark_job_canceled(job_id, progress=10, message="Host kesfi kullanici tarafindan iptal edildi.")
            return None

        now = time.time()
        if now - last_live_update >= 2:
            ratio = min((now - discovery_started_at) / max_discovery_seconds, 0.95)
            progress = min(18, 8 + int(round(ratio * 10)))
            _update_job(
                job_id,
                progress=progress,
                message="Subnet icindeki canli hostlar kesfediliyor.",
                current_step="nmap",
            )
            last_live_update = now

        if now - discovery_started_at > max_discovery_seconds:
            discovery_timed_out = True
            try:
                process.terminate()
                process.wait(timeout=3)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
            break

        threading.Event().wait(0.5)

    try:
        _, stderr = process.communicate(timeout=2)
    except Exception:
        stderr = ""
    _update_job(job_id, process=None)

    if process.returncode != 0:
        error_detail = str(stderr).strip()
        if discovery_timed_out:
            error_detail = error_detail or "Host kesfi zaman asimina ugradi."
            partial_hosts = _load_discovery_hosts_best_effort(workspace["discovery_xml_path"], target)
            if partial_hosts:
                _update_job(
                    job_id,
                    progress=20,
                    message=f"Host kesfi zaman asimina ugradi, bulunan {len(partial_hosts)} host ile devam ediliyor.",
                    current_step="nmap",
                    log_message=f"Host kesfi zaman asimina ugradi ancak {len(partial_hosts)} host bulundu; tarama bu hostlarla suruyor.",
                    log_level="warn",
                )
                return partial_hosts
        _update_job(
            job_id,
            status="failed",
            progress=100,
            error=f"Host kesfi hatasi: {error_detail}",
            message="Subnet host kesfi tamamlanamadi.",
            log_message=f"Host kesfi hatasi alindi: {error_detail or 'Bilinmeyen hata'}",
            log_level="error",
        )
        return None

    active_hosts = _load_discovery_hosts_best_effort(workspace["discovery_xml_path"], target)

    if not active_hosts:
        _update_job(
            job_id,
            status="failed",
            progress=100,
            error="Subnet icinde erisilebilir host bulunamadi.",
            message="Canli host bulunamadigi icin detay tarama baslatilamadi.",
            log_message="Host kesfi tamamlandi ancak canli host bulunamadi.",
            log_level="warn",
        )
        return None

    _update_job(
        job_id,
        progress=20,
        message=f"{len(active_hosts)} aktif host bulundu. Detay tarama baslatiliyor.",
        current_step="nmap",
        log_message=f"Host kesfi tamamlandi, {len(active_hosts)} aktif host bulundu.",
    )
    return active_hosts


def _build_nmap_live_progress(target, scan_started_at, max_scan_seconds, xml_path):
    elapsed_seconds = max(0, time.time() - scan_started_at)
    time_ratio = min(elapsed_seconds / max(max_scan_seconds, 1), 0.98)
    discovered_hosts = 0
    progress_floor = 20 if isinstance(target, (list, tuple, set)) else 8

    try:
        if os.path.exists(xml_path):
            with open(xml_path, "r", encoding="utf-8", errors="ignore") as handle:
                xml_text = handle.read()
            discovered_hosts = max(xml_text.count("<hosthint>"), xml_text.count("<host>"))
    except OSError:
        discovered_hosts = 0

    target_size = _estimate_target_size(target)
    discovery_ratio = 0.0
    if target_size > 1 and discovered_hosts > 0:
        discovery_ratio = min(discovered_hosts / target_size, 1.0)
    elif discovered_hosts > 0:
        discovery_ratio = 0.35

    progress_ratio = max(time_ratio * 0.85, discovery_ratio)
    live_progress = min(28, progress_floor + int(round(progress_ratio * (28 - progress_floor))))

    if discovered_hosts > 0:
        live_message = (
            f"Host kesfi ve port tarama suruyor. "
            f"Su ana kadar {discovered_hosts} host ipucu bulundu."
        )
    else:
        live_message = "Host kesfi ve port tarama suruyor. Nmap ara sonuclari bekleniyor."

    return live_progress, live_message


def _should_retry_with_quick_scan(network_summary, host_reports, scan_type, nse_scripts):
    if scan_type not in {"detailed", "vuln"} and not nse_scripts:
        return False
    if not host_reports:
        return False

    any_timeout = any(host.get("scan_timed_out") for host in host_reports)
    any_open_port = any(host.get("total_open_ports", 0) > 0 for host in host_reports)
    return any_timeout and not any_open_port and network_summary.get("total_hosts", 0) > 0


def _run_scan_job(job_id, target, team_mode, scan_type, nse_scripts, port_scope, port_spec):
    try:
        job = _get_job(job_id)
        workspace = (job or {}).get("workspace") or _job_workspace(job_id)
        nse_script_labels = get_nse_script_labels(nse_scripts)
        port_label = get_port_label(port_scope, port_spec)
        subnet_target = is_subnet_target(target)
        scan_message = f"{get_scan_label(scan_type)} baslatiliyor."
        scan_message += f" {port_label}."
        if nse_script_labels:
            scan_message += f" NSE: {', '.join(nse_script_labels)}."
        if subnet_target and scan_type != "ping":
            scan_message += " Subnet hedefi oldugu icin once canli host kesfi yapilacak."
        _update_job(
            job_id,
            status="running",
            progress=8,
            message=scan_message,
            current_step="nmap",
            log_message=f"Host kesfi ve port tarama baslatildi. Profil: {get_scan_label(scan_type)} | {port_label}"
            + (f" | NSE: {', '.join(nse_script_labels)}" if nse_script_labels else ""),
        )
        scan_target = target
        if subnet_target and scan_type != "ping":
            scan_target = _run_discovery_phase(job_id, target)
            if scan_target is None:
                return

        process = start_nmap_scan(scan_target, scan_type, nse_scripts, port_scope, port_spec, output_xml_path=workspace["xml_path"])
        _update_job(job_id, process=process)

        target_size = _estimate_target_size(scan_target)
        if target_size > 1:
            _max_scan_seconds = min(420, 120 + (target_size * 25))
        else:
            _max_scan_seconds = 300 if scan_type in {"detailed", "vuln"} or nse_scripts else 180
        _scan_start = time.time()
        _timed_out = False
        _last_live_update = 0

        while process.poll() is None:
            if _job_cancel_requested(job_id):
                _stop_job_process(job_id)
                _mark_job_canceled(job_id, progress=12, message="Tarama kullanici tarafindan iptal edildi.")
                return
            now = time.time()
            if now - _last_live_update >= 2:
                live_progress, live_message = _build_nmap_live_progress(scan_target, _scan_start, _max_scan_seconds, workspace["xml_path"])
                _update_job(job_id, progress=live_progress, message=live_message, current_step="nmap")
                _last_live_update = now
            if now - _scan_start > _max_scan_seconds:
                _timed_out = True
                _update_job(job_id, log_message=f"Tarama suresi asimi ({_max_scan_seconds}sn), mevcut sonuclar isleniyor.", log_level="warn")
                try:
                    process.terminate()
                    process.wait(timeout=3)
                except Exception:
                    try:
                        process.kill()
                    except Exception:
                        pass
                break
            threading.Event().wait(0.5)

        try:
            _, stderr = process.communicate(timeout=2)
        except Exception:
            stderr = b""
        _update_job(job_id, process=None)

        if not _timed_out and process.returncode != 0:
            _update_job(
                job_id,
                status="failed",
                progress=100,
                error=f"Nmap hatasi: {stderr}",
                message="Tarama basarisiz oldu.",
                log_message=f"Nmap hatasi alindi: {stderr.strip() or 'Bilinmeyen hata'}",
                log_level="error",
            )
            return

        if _check_for_cancel(job_id, 30, "Tarama XML cozumleme oncesi iptal edildi."):
            return
        _update_job(
            job_id,
            progress=30,
            message="Host kesfi tamamlandi, port tarama sonuclari isleniyor.",
            current_step="parse",
            log_message="Host kesfi ve port tarama tamamlandi, sonuc isleme basladi.",
        )
        network_summary, host_reports = parse_results(workspace["xml_path"])

        retryable_hosts = _retryable_timed_out_hosts(host_reports)
        if retryable_hosts:
            network_summary, host_reports, refreshed_count = _retry_timed_out_hosts(
                job_id,
                host_reports,
                port_scope,
                port_spec,
            )
            if refreshed_count:
                _update_job(
                    job_id,
                    log_message=(
                        f"Zaman asimina ugrayan hostlar tek tek yeniden tarandi; "
                        f"{refreshed_count} host icin port listesi yenilendi."
                    ),
                    log_level="warn",
                )

        if _should_retry_with_quick_scan(network_summary, host_reports, scan_type, nse_scripts):
            _update_job(
                job_id,
                progress=36,
                message="Detayli tarama zaman asimina ugradi. Hafif tarama ile yeniden deneniyor.",
                current_step="nmap",
                log_message="Host yanit verdi ancak detayli tarama zaman asimina ugradi. Daha hafif bir quick tarama baslatiliyor.",
                log_level="warn",
            )
            retry_process = start_nmap_scan(scan_target, "quick", [], port_scope, port_spec, output_xml_path=workspace["xml_path"])
            _update_job(job_id, process=retry_process)

            retry_started_at = time.time()
            retry_timed_out = False
            while retry_process.poll() is None:
                if _job_cancel_requested(job_id):
                    _stop_job_process(job_id)
                    _mark_job_canceled(job_id, progress=38, message="Yeniden deneme taramasi kullanici tarafindan iptal edildi.")
                    return
                if time.time() - retry_started_at > 150:
                    retry_timed_out = True
                    _update_job(
                        job_id,
                        log_message="Quick yeniden deneme de zaman asimina ugradi; mevcut sonuclar kullanilacak.",
                        log_level="warn",
                    )
                    try:
                        retry_process.terminate()
                        retry_process.wait(timeout=3)
                    except Exception:
                        try:
                            retry_process.kill()
                        except Exception:
                            pass
                    break
                threading.Event().wait(0.5)

            try:
                retry_process.communicate(timeout=2)
            except Exception:
                pass
            _update_job(job_id, process=None)

            if not retry_timed_out and retry_process.returncode == 0:
                network_summary, host_reports = parse_results(workspace["xml_path"])
                _update_job(
                    job_id,
                    log_message="Quick yeniden deneme tamamlandi ve sonuclar guncellendi.",
                )

        if _check_for_cancel(job_id, 48, "Tarama CVE zenginlestirme oncesi iptal edildi."):
            return
        _update_job(
            job_id,
            progress=48,
            message="Versiyon ve zafiyet analizi yapiliyor.",
            current_step="cve",
            log_message="Versiyon ve zafiyet analizi asamasina gecildi.",
        )
        enrich_reports_with_online_cves(network_summary, host_reports)
        _attach_udp_summary(network_summary, host_reports)
        _attach_nse_summary(network_summary, host_reports)

        if _check_for_cancel(job_id, 62, "Tarama senaryo uretimi oncesi iptal edildi."):
            return
        _update_job(
            job_id,
            progress=62,
            message="Bulgular yorumlaniyor ve saldiri senaryolari hazirlaniyor.",
            current_step="scenario",
            log_message="Bulgular yorumlanmaya baslandi, senaryo uretimi suruyor.",
        )
        generate_attack_scenarios(network_summary, host_reports)

        if _check_for_cancel(job_id, 72, "Tarama takim modu analizi oncesi iptal edildi."):
            return
        _update_job(
            job_id,
            progress=72,
            message="Red Team / Blue Team degerlendirmesi yapiliyor.",
            current_step="team",
            log_message="Takim modu degerlendirmesi basladi.",
        )
        apply_team_mode_analysis(network_summary, host_reports)

        if _check_for_cancel(job_id, 80, "Tarama gecmis karsilastirma oncesi iptal edildi."):
            return
        _update_job(
            job_id,
            progress=80,
            message="Gecmis taramalarla karsilastirma yapiliyor.",
            current_step="history",
            log_message="Gecmis tarama karsilastirmasi basladi.",
        )
        comparison = record_and_compare_scan(target, network_summary, host_reports)

        if _check_for_cancel(job_id, 88, "Tarama grafik olusturma oncesi iptal edildi."):
            return
        _update_job(
            job_id,
            progress=88,
            message="Grafikler ve topoloji gorselleri hazirlaniyor.",
            current_step="charts",
            log_message="Grafik ve topoloji hazirlama basladi.",
        )
        generate_risk_chart(network_summary)
        generate_os_chart(network_summary)
        generate_network_topology(target, network_summary)

        if _check_for_cancel(job_id, 95, "Tarama rapor olusturma oncesi iptal edildi."):
            return
        _update_job(
            job_id,
            progress=95,
            message="Raporlama tamamlanmak uzere, ciktilar olusturuluyor.",
            current_step="reports",
            log_message="Rapor olusturma asamasi basladi.",
        )
        generate_reports(network_summary, host_reports, comparison, mode=team_mode)
        _archive_job_outputs(job_id)
        record_scan_history(target, scan_type, get_scan_label(scan_type), team_mode, network_summary, host_reports)

        _update_job(
            job_id,
            status="completed",
            progress=100,
            message="Tarama tamamlandi. Sonuclar ve raporlar hazir.",
            current_step="completed",
            result={
                "network_summary": network_summary,
                "host_reports": host_reports,
                "comparison": comparison,
            },
            cancel_requested=False,
            log_message="Tarama ve raporlama basariyla tamamlandi.",
        )
    except ValueError as parse_error:
        _update_job(
            job_id,
            status="failed",
            progress=100,
            error=str(parse_error),
            message="Analiz tamamlanamadi.",
            process=None,
            log_message=f"Analiz hatasi: {parse_error}",
            log_level="error",
        )
    except Exception as unexpected_error:
        _update_job(
            job_id,
            status="failed",
            progress=100,
            error=f"Beklenmeyen hata: {unexpected_error}",
            message="Tarama beklenmeyen bir hata ile sonlandi.",
            process=None,
            log_message=f"Beklenmeyen hata: {unexpected_error}",
            log_level="error",
        )


@app.route("/", methods=["GET"])
def index():
    network_summary = None
    host_reports = None
    comparison = None
    error = None
    target = request.args.get("target", "").strip()
    team_mode = request.args.get("team_mode", RED_TEAM).strip().lower()
    scan_type = request.args.get("scan_type", "detailed").strip().lower()
    port_scope = normalize_port_scope(request.args.get("port_scope", "default"))
    port_spec = ""
    auto_start = request.args.get("autostart", "").strip().lower() in {"1", "true", "yes"}
    selected_nse_scripts = []
    recent_history = get_recent_scan_history()
    risk_chart_url = url_for("static", filename="risk_chart.png")
    os_chart_url = url_for("static", filename="os_distribution.png")
    topology_chart_url = url_for("static", filename="network_topology.png")
    report_html_url = "/report"
    report_txt_url = "/report/txt"
    report_pdf_url = "/report/pdf"
    export_previews = []
    compare_candidates = get_history_compare_candidates()
    history_compare = None
    selected_compare_left = request.args.get("compare_left", "").strip()
    selected_compare_right = request.args.get("compare_right", "").strip()
    view_mode = request.args.get("view", "manager").strip().lower()
    if view_mode not in {"manager", "technical"}:
        view_mode = "manager"

    if team_mode not in {RED_TEAM, BLUE_TEAM}:
        team_mode = RED_TEAM
    if scan_type not in SCAN_PROFILES:
        scan_type = "detailed"

    job_id = request.args.get("job", "").strip()
    if job_id:
        job = _get_job(job_id)
        if job is None:
            error = "Tarama oturumu bulunamadi."
        else:
            target = job.get("target", "")
            team_mode = job.get("team_mode", RED_TEAM)
            scan_type = job.get("scan_type", "detailed")
            port_scope = normalize_port_scope(job.get("port_scope", "default"))
            port_spec = job.get("port_spec", "")
            selected_nse_scripts = job.get("nse_scripts", [])
            if job.get("status") == "completed" and job.get("result"):
                result = job["result"]
                network_summary = result.get("network_summary")
                host_reports = result.get("host_reports")
                comparison = result.get("comparison")
                chart_urls = job.get("chart_urls", {})
                report_urls = job.get("report_urls", {})
                risk_chart_url = chart_urls.get("risk", risk_chart_url)
                os_chart_url = chart_urls.get("os", os_chart_url)
                topology_chart_url = chart_urls.get("topology", topology_chart_url)
                report_html_url = report_urls.get("html", report_html_url)
                report_txt_url = report_urls.get("txt", report_txt_url)
                report_pdf_url = report_urls.get("pdf", report_pdf_url)
            elif job.get("status") == "canceled":
                error = job.get("message") or "Tarama iptal edildi."
            elif job.get("status") == "failed":
                error = job.get("error") or "Tarama tamamlanamadi."

            export_previews = _build_export_previews(
                report_html_url,
                report_pdf_url,
                report_txt_url,
                workspace=job.get("workspace"),
            )

    if not export_previews:
        export_previews = _build_export_previews(report_html_url, report_pdf_url, report_txt_url)

    if selected_compare_left and selected_compare_right:
        try:
            history_compare = build_history_compare_data(int(selected_compare_left), int(selected_compare_right))
        except ValueError:
            history_compare = None

    return render_template(
        "index.html",
        network_summary=network_summary,
        host_reports=host_reports,
        comparison=comparison,
        error=error,
        target=target,
        team_mode=team_mode,
        scan_type=scan_type,
        port_scope=port_scope,
        port_spec=port_spec,
        scan_profiles=SCAN_PROFILES,
        port_scope_options=PORT_SCOPE_OPTIONS,
        nse_script_options=NSE_SCRIPT_OPTIONS,
        selected_nse_scripts=selected_nse_scripts,
        recent_history=recent_history,
        auto_start=auto_start,
        risk_chart_url=risk_chart_url,
        os_chart_url=os_chart_url,
        topology_chart_url=topology_chart_url,
        report_html_url=report_html_url,
        report_txt_url=report_txt_url,
        report_pdf_url=report_pdf_url,
        export_previews=export_previews,
        compare_candidates=compare_candidates,
        history_compare=history_compare,
        selected_compare_left=selected_compare_left,
        selected_compare_right=selected_compare_right,
        view_mode=view_mode,
        job_id=job_id,
    )


@app.route("/discovery", methods=["GET", "POST"])
def discovery():
    target = ""
    discovery_result = None
    discovery_comparison = None
    error = None

    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if not target:
            error = "Lutfen bir subnet girin. Ornek: 192.168.1.0/24"
        else:
            try:
                target = validate_target_value(target)
                success, stderr = run_ping_discovery(target)
                if not success:
                    error = f"Nmap hatasi: {stderr}"
                else:
                    discovery_result = parse_discovery_results()
                    discovery_result["target"] = target
                    discovery_comparison = record_and_compare_discovery(target, discovery_result)
                    new_device_ips = {device["ip"] for device in discovery_comparison.get("new_devices", [])}
                    for device in discovery_result.get("devices", []):
                        device["is_new"] = device.get("ip") in new_device_ips
                    generate_discovery_topology(target, discovery_result.get("devices", []))
            except ValueError as parse_error:
                error = str(parse_error)

    return render_template(
        "discovery.html",
        target=target,
        discovery_result=discovery_result,
        discovery_comparison=discovery_comparison,
        error=error,
    )


@app.route("/history/<int:history_id>")
def history_detail(history_id):
    history_item = get_scan_history_detail(history_id)
    if history_item is None:
        return Response("Tarama gecmisi bulunamadi.", status=404, mimetype="text/plain; charset=utf-8")

    return render_template("history_detail.html", history_item=history_item)


@app.route("/history")
def history_archive():
    grouped_history = get_scan_history_archive()
    return render_template("history_archive.html", grouped_history=grouped_history)


@app.route("/scan/start", methods=["POST"])
def start_scan():
    target = request.form.get("target", "").strip()
    team_mode = request.form.get("team_mode", RED_TEAM).strip().lower()
    scan_type = request.form.get("scan_type", "detailed").strip().lower()
    port_scope = normalize_port_scope(request.form.get("port_scope", "default"))
    nse_scripts = normalize_nse_scripts(request.form.getlist("nse_scripts"))
    if team_mode not in {RED_TEAM, BLUE_TEAM}:
        team_mode = RED_TEAM
    if scan_type not in SCAN_PROFILES:
        scan_type = "detailed"

    if not target:
        return jsonify({"ok": False, "error": "Lutfen hedef IP veya ag araligi girin."}), 400

    try:
        target = validate_target_value(target)
    except ValueError as validation_error:
        return jsonify({"ok": False, "error": str(validation_error)}), 400

    if _has_active_scan():
        return jsonify({"ok": False, "error": "Ayni anda yalnizca bir tarama calistirilabilir. Once mevcut taramanin bitmesini bekleyin."}), 409

    try:
        port_spec = normalize_port_spec(port_scope, request.form.get("port_spec", ""))
    except ValueError as validation_error:
        return jsonify({"ok": False, "error": str(validation_error)}), 400

    job = _create_job(target, team_mode, scan_type, nse_scripts, port_scope, port_spec)
    worker = threading.Thread(
        target=_run_scan_job,
        args=(job["id"], target, team_mode, scan_type, nse_scripts, port_scope, port_spec),
        daemon=True,
    )
    worker.start()
    return jsonify({"ok": True, "job_id": job["id"]})


@app.route("/scan-cancel/<job_id>", methods=["POST"])
def cancel_scan(job_id):
    job = _get_job(job_id)
    if job is None:
        return jsonify({"ok": False, "error": "Tarama oturumu bulunamadi."}), 404

    if job.get("status") in {"completed", "failed", "canceled"}:
        return jsonify({"ok": False, "error": "Bu tarama artik iptal edilemez."}), 400

    _update_job(job_id, cancel_requested=True, message="Iptal istegi alindi, tarama durduruluyor.")
    _stop_job_process(job_id)
    return jsonify({"ok": True})


@app.route("/scan-status/<job_id>")
def scan_status(job_id):
    job = _get_job(job_id)
    if job is None:
        return jsonify({"ok": False, "error": "Tarama oturumu bulunamadi."}), 404

    response = jsonify(
        {
            "ok": True,
            "job_id": job["id"],
            "target": job["target"],
            "team_mode": job["team_mode"],
            "scan_type": job.get("scan_type", "detailed"),
            "scan_label": job.get("scan_label", get_scan_label("detailed")),
            "port_scope": job.get("port_scope", "default"),
            "port_spec": job.get("port_spec", ""),
            "port_label": job.get("port_label", "Varsayilan Portlar"),
            "nse_scripts": job.get("nse_scripts", []),
            "nse_script_labels": job.get("nse_script_labels", []),
            "status": job["status"],
            "progress": job["progress"],
            "message": job["message"],
            "error": job["error"],
            "current_step": job.get("current_step"),
            "logs": job.get("logs", []),
            "result_url": f"/?job={job['id']}" if job["status"] == "completed" else None,
        }
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/report")
def download_report():
    job_id = request.args.get("job", "").strip()
    if job_id:
        job = _get_job(job_id)
        if job is None:
            return _response_not_found("Tarama oturumu bulunamadi.")
        if not os.path.exists(job["workspace"]["html_report_path"]):
            return _response_not_found("HTML raporu bulunamadi.")
        return send_file(job["workspace"]["html_report_path"])
    if not os.path.exists(HTML_RAPOR_DOSYASI):
        return _response_not_found("HTML raporu bulunamadi.")
    return send_file(HTML_RAPOR_DOSYASI)


@app.route("/report/txt")
def download_text_report():
    job_id = request.args.get("job", "").strip()
    if job_id:
        job = _get_job(job_id)
        if job is None:
            return _response_not_found("Tarama oturumu bulunamadi.")
        if not os.path.exists(job["workspace"]["txt_report_path"]):
            return _response_not_found("TXT raporu bulunamadi.")
        return send_file(job["workspace"]["txt_report_path"], mimetype="text/plain; charset=utf-8")
    if not os.path.exists(TXT_RAPOR_DOSYASI):
        return _response_not_found("TXT raporu bulunamadi.")
    return send_file(TXT_RAPOR_DOSYASI, mimetype="text/plain; charset=utf-8")


@app.route("/report/pdf")
def printable_report():
    job_id = request.args.get("job", "").strip()
    if job_id:
        job = _get_job(job_id)
        if job is None:
            return _response_not_found("Tarama oturumu bulunamadi.")
        workspace = job["workspace"]
        if can_generate_pdf() and os.path.exists(workspace["pdf_report_path"]):
            return send_file(
                workspace["pdf_report_path"],
                mimetype="application/pdf",
                as_attachment=True,
                download_name=f"report-{job_id}.pdf",
            )
        if os.path.exists(workspace["html_report_path"]):
            return send_file(workspace["html_report_path"], mimetype="text/html; charset=utf-8")
        return _response_not_found("PDF veya yazdirilabilir rapor bulunamadi.")
    if can_generate_pdf() and os.path.exists(PDF_RAPOR_DOSYASI):
        return send_file(
            PDF_RAPOR_DOSYASI,
            mimetype="application/pdf",
            as_attachment=True,
            download_name="report.pdf",
        )

    if not os.path.exists(HTML_RAPOR_DOSYASI):
        return _response_not_found("PDF veya yazdirilabilir rapor bulunamadi.")

    html = build_printable_report_html()
    if html is None:
        return Response("PDF icin once bir rapor olusturun.", status=404, mimetype="text/plain; charset=utf-8")
    return Response(html, mimetype="text/html; charset=utf-8")


@app.route("/job-artifact/<job_id>/<artifact_name>")
def job_artifact(job_id, artifact_name):
    job = _get_job(job_id)
    if job is None:
        return Response("Tarama oturumu bulunamadi.", status=404, mimetype="text/plain; charset=utf-8")

    artifact_map = {
        "risk_chart.png": job["workspace"]["risk_chart_path"],
        "os_distribution.png": job["workspace"]["os_chart_path"],
        "network_topology.png": job["workspace"]["topology_chart_path"],
    }
    path = artifact_map.get(artifact_name)
    if not path or not os.path.exists(path):
        return Response("Artefakt bulunamadi.", status=404, mimetype="text/plain; charset=utf-8")
    return send_file(path)


if __name__ == "__main__":
    os.makedirs(os.path.join(app.root_path, "static"), exist_ok=True)
    init_history_db()
    # Tarama sonrasi uretilen rapor/gorsel dosyalari Flask reloader'ini tetikleyip
    # gelistirme sunucusunun yeniden baslamasina neden olabiliyor.
    app.run(debug=False, use_reloader=False)
