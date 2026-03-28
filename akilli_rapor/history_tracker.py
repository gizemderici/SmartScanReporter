import json
import os
import re
from datetime import datetime


BASE_DIR = os.path.dirname(__file__)
HISTORY_DIR = os.path.join(BASE_DIR, "history")


def _safe_target_name(target: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target.strip())
    return safe or "unknown_target"


def _snapshot_path(target: str) -> str:
    return os.path.join(HISTORY_DIR, f"{_safe_target_name(target)}.json")


def build_snapshot(target: str, network_summary, host_reports):
    hosts = []
    for host in host_reports:
        hosts.append(
            {
                "ip": host["ip"],
                "general_risk": host["general_risk"],
                "host_score": host["host_score"],
                "open_ports": [
                    {
                        "port": port["port"],
                        "protocol": port["protocol"],
                        "service": port["service"],
                        "service_version": port.get("service_version", "Bilinmiyor"),
                        "risk": port["risk"],
                    }
                    for port in host["open_ports_data"]
                ],
            }
        )

    return {
        "target": target,
        "captured_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "network_summary": {
            "total_hosts": network_summary["total_hosts"],
            "high_risk_hosts": network_summary["high_risk_hosts"],
            "medium_risk_hosts": network_summary["medium_risk_hosts"],
            "low_risk_hosts": network_summary["low_risk_hosts"],
            "total_known_cves": network_summary.get("total_known_cves", 0),
        },
        "hosts": hosts,
    }


def load_previous_snapshot(target: str):
    path = _snapshot_path(target)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_snapshot(target: str, snapshot):
    os.makedirs(HISTORY_DIR, exist_ok=True)
    with open(_snapshot_path(target), "w", encoding="utf-8") as file:
        json.dump(snapshot, file, ensure_ascii=False, indent=2)


def compare_snapshots(previous_snapshot, current_snapshot):
    if not previous_snapshot:
        return {
            "has_previous": False,
            "previous_scan_time": None,
            "current_scan_time": current_snapshot["captured_at"],
            "new_ports": [],
            "closed_ports": [],
            "risk_changes": [],
            "summary": {
                "new_port_count": 0,
                "closed_port_count": 0,
                "risk_increase_count": 0,
            },
        }

    previous_hosts = {host["ip"]: host for host in previous_snapshot.get("hosts", [])}
    current_hosts = {host["ip"]: host for host in current_snapshot.get("hosts", [])}
    new_ports = []
    closed_ports = []
    risk_changes = []

    for ip in sorted(set(previous_hosts) | set(current_hosts)):
        previous_host = previous_hosts.get(ip, {"open_ports": [], "general_risk": "Bilinmiyor", "host_score": 0})
        current_host = current_hosts.get(ip, {"open_ports": [], "general_risk": "Bilinmiyor", "host_score": 0})

        previous_ports = {(port["port"], port["protocol"]): port for port in previous_host.get("open_ports", [])}
        current_ports = {(port["port"], port["protocol"]): port for port in current_host.get("open_ports", [])}

        for key, port in current_ports.items():
            if key not in previous_ports:
                new_ports.append(
                    {
                        "ip": ip,
                        "port": port["port"],
                        "protocol": port["protocol"],
                        "service": port["service"],
                        "service_version": port.get("service_version", "Bilinmiyor"),
                    }
                )

        for key, port in previous_ports.items():
            if key not in current_ports:
                closed_ports.append(
                    {
                        "ip": ip,
                        "port": port["port"],
                        "protocol": port["protocol"],
                        "service": port["service"],
                        "service_version": port.get("service_version", "Bilinmiyor"),
                    }
                )

        previous_score = previous_host.get("host_score", 0)
        current_score = current_host.get("host_score", 0)
        previous_risk = previous_host.get("general_risk", "Bilinmiyor")
        current_risk = current_host.get("general_risk", "Bilinmiyor")

        if previous_score != current_score or previous_risk != current_risk:
            risk_changes.append(
                {
                    "ip": ip,
                    "previous_risk": previous_risk,
                    "current_risk": current_risk,
                    "previous_score": previous_score,
                    "current_score": current_score,
                    "direction": "arttı" if current_score > previous_score else "azaldı" if current_score < previous_score else "değişti",
                }
            )

    return {
        "has_previous": True,
        "previous_scan_time": previous_snapshot.get("captured_at"),
        "current_scan_time": current_snapshot.get("captured_at"),
        "new_ports": new_ports,
        "closed_ports": closed_ports,
        "risk_changes": risk_changes,
        "summary": {
            "new_port_count": len(new_ports),
            "closed_port_count": len(closed_ports),
            "risk_increase_count": sum(1 for item in risk_changes if item["current_score"] > item["previous_score"]),
        },
    }


def record_and_compare_scan(target: str, network_summary, host_reports):
    previous_snapshot = load_previous_snapshot(target)
    current_snapshot = build_snapshot(target, network_summary, host_reports)
    comparison = compare_snapshots(previous_snapshot, current_snapshot)
    save_snapshot(target, current_snapshot)
    return comparison
