import json
import os
import sqlite3
from datetime import datetime


BASE_DIR = os.path.dirname(__file__)
DATABASE_PATH = os.path.join(BASE_DIR, "database.db")


def get_connection():
    return sqlite3.connect(DATABASE_PATH)


def init_history_db():
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                scan_label TEXT NOT NULL,
                team_mode TEXT NOT NULL,
                total_hosts INTEGER NOT NULL DEFAULT 0,
                high_risk_hosts INTEGER NOT NULL DEFAULT 0,
                total_known_cves INTEGER NOT NULL DEFAULT 0,
                detail_json TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(scan_history)").fetchall()
        }
        if "detail_json" not in columns:
            connection.execute("ALTER TABLE scan_history ADD COLUMN detail_json TEXT")
        connection.commit()


def _build_detail_payload(network_summary, host_reports):
    host_items = []
    for host in host_reports[:8]:
        host_items.append(
            {
                "ip": host.get("ip", "Bilinmiyor"),
                "detected_os": host.get("detected_os", "Bilinmiyor"),
                "general_risk": host.get("general_risk", "Bilinmiyor"),
                "host_score": host.get("host_score", 0),
                "total_open_ports": host.get("total_open_ports", 0),
                "total_filtered_ports": host.get("total_filtered_ports", 0),
                "scan_timed_out": bool(host.get("scan_timed_out", False)),
            }
        )

    return {
        "most_risky_host": network_summary.get("most_risky_host", "Yok"),
        "medium_risk_hosts": network_summary.get("medium_risk_hosts", 0),
        "low_risk_hosts": network_summary.get("low_risk_hosts", 0),
        "total_filtered_ports": network_summary.get("total_filtered_ports", 0),
        "timed_out_hosts": network_summary.get("timed_out_hosts", 0),
        "scenario_count": network_summary.get("scenario_count", 0),
        "mitre_technique_count": network_summary.get("mitre_technique_count", 0),
        "hosts": host_items,
    }


def record_scan_history(target, scan_type, scan_label, team_mode, network_summary, host_reports):
    captured_at = datetime.now().astimezone().isoformat(timespec="seconds")
    detail_json = json.dumps(_build_detail_payload(network_summary, host_reports), ensure_ascii=False)
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO scan_history (
                target, scan_type, scan_label, team_mode,
                total_hosts, high_risk_hosts, total_known_cves, detail_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target,
                scan_type,
                scan_label,
                team_mode,
                int(network_summary.get("total_hosts", 0)),
                int(network_summary.get("high_risk_hosts", 0)),
                int(network_summary.get("total_known_cves", 0)),
                detail_json,
                captured_at,
            ),
        )
        connection.commit()


def _parse_detail_json(raw_detail):
    if not raw_detail:
        return {}
    try:
        return json.loads(raw_detail)
    except json.JSONDecodeError:
        return {}


def _group_label(created_at_text):
    try:
        created_at = datetime.fromisoformat(created_at_text)
    except ValueError:
        return "Daha Eski"

    now = datetime.now(created_at.tzinfo).astimezone()
    today = now.date()
    created_date = created_at.date()
    delta_days = (today - created_date).days

    if delta_days <= 0:
        return "Bugun"
    if delta_days == 1:
        return "Dun"
    return "Daha Eski"


def get_recent_scan_history(limit=12):
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, target, scan_type, scan_label, team_mode,
                   total_hosts, high_risk_hosts, total_known_cves, created_at
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()

    grouped = {"Bugun": [], "Dun": [], "Daha Eski": []}

    for row in rows:
        item = {
            "id": row[0],
            "target": row[1],
            "scan_type": row[2],
            "scan_label": row[3],
            "team_mode": row[4],
            "total_hosts": row[5],
            "high_risk_hosts": row[6],
            "total_known_cves": row[7],
            "created_at": row[8],
        }
        grouped[_group_label(row[8])].append(item)

    return grouped


def get_scan_history_archive(limit=250):
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, target, scan_type, scan_label, team_mode,
                   total_hosts, high_risk_hosts, total_known_cves, created_at
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()

    grouped = {"Bugun": [], "Dun": [], "Daha Eski": []}

    for row in rows:
        item = {
            "id": row[0],
            "target": row[1],
            "scan_type": row[2],
            "scan_label": row[3],
            "team_mode": row[4],
            "total_hosts": row[5],
            "high_risk_hosts": row[6],
            "total_known_cves": row[7],
            "created_at": row[8],
        }
        grouped[_group_label(row[8])].append(item)

    grouped["total_count"] = len(rows)
    return grouped


def get_history_compare_candidates(limit=24):
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, target, scan_type, scan_label, team_mode,
                   total_hosts, high_risk_hosts, total_known_cves, created_at
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()

    items = []
    for row in rows:
        items.append(
            {
                "id": row[0],
                "target": row[1],
                "scan_type": row[2],
                "scan_label": row[3],
                "team_mode": row[4],
                "total_hosts": row[5],
                "high_risk_hosts": row[6],
                "total_known_cves": row[7],
                "created_at": row[8],
                "label": f"#{row[0]} | {row[1]} | {row[3]} | {row[8]}",
            }
        )
    return items


def get_scan_history_item(history_id):
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, target, scan_type, scan_label, team_mode,
                   total_hosts, high_risk_hosts, total_known_cves, detail_json, created_at
            FROM scan_history
            WHERE id = ?
            """,
            (int(history_id),),
        ).fetchone()

    if row is None:
        return None

    return {
        "id": row[0],
        "target": row[1],
        "scan_type": row[2],
        "scan_label": row[3],
        "team_mode": row[4],
        "total_hosts": row[5],
        "high_risk_hosts": row[6],
        "total_known_cves": row[7],
        "detail": _parse_detail_json(row[8]),
        "created_at": row[9],
    }


def build_history_compare_data(left_history_id, right_history_id):
    left = get_scan_history_item(left_history_id)
    right = get_scan_history_item(right_history_id)
    if left is None or right is None:
        return None

    left_hosts = {host.get("ip"): host for host in left.get("detail", {}).get("hosts", [])}
    right_hosts = {host.get("ip"): host for host in right.get("detail", {}).get("hosts", [])}

    new_hosts = []
    missing_hosts = []
    risk_changes = []

    for ip in sorted(set(left_hosts) | set(right_hosts)):
        left_host = left_hosts.get(ip)
        right_host = right_hosts.get(ip)
        if left_host is None and right_host is not None:
            new_hosts.append(
                {
                    "ip": ip,
                    "risk": right_host.get("general_risk", "Bilinmiyor"),
                    "score": right_host.get("host_score", 0),
                }
            )
            continue
        if right_host is None and left_host is not None:
            missing_hosts.append(
                {
                    "ip": ip,
                    "risk": left_host.get("general_risk", "Bilinmiyor"),
                    "score": left_host.get("host_score", 0),
                }
            )
            continue

        left_score = left_host.get("host_score", 0)
        right_score = right_host.get("host_score", 0)
        left_risk = left_host.get("general_risk", "Bilinmiyor")
        right_risk = right_host.get("general_risk", "Bilinmiyor")
        if left_score != right_score or left_risk != right_risk:
            direction = "degisti"
            if right_score > left_score:
                direction = "artti"
            elif right_score < left_score:
                direction = "azaldi"
            risk_changes.append(
                {
                    "ip": ip,
                    "left_risk": left_risk,
                    "right_risk": right_risk,
                    "left_score": left_score,
                    "right_score": right_score,
                    "direction": direction,
                }
            )

    left_detail = left.get("detail", {})
    right_detail = right.get("detail", {})

    return {
        "left": left,
        "right": right,
        "summary": {
            "host_delta": right["total_hosts"] - left["total_hosts"],
            "high_risk_delta": right["high_risk_hosts"] - left["high_risk_hosts"],
            "cve_delta": right["total_known_cves"] - left["total_known_cves"],
            "scenario_delta": right_detail.get("scenario_count", 0) - left_detail.get("scenario_count", 0),
            "mitre_delta": right_detail.get("mitre_technique_count", 0) - left_detail.get("mitre_technique_count", 0),
            "timed_out_delta": right_detail.get("timed_out_hosts", 0) - left_detail.get("timed_out_hosts", 0),
        },
        "new_hosts": new_hosts,
        "missing_hosts": missing_hosts,
        "risk_changes": risk_changes,
    }


def get_scan_history_detail(history_id):
    return get_scan_history_item(history_id)
