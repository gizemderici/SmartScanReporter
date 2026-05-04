RED_TEAM = "red"
BLUE_TEAM = "blue"

HIGH_RISK_PORTS = {23, 139, 445, 3389}
BRUTE_FORCE_PORTS = {21, 22, 3389}


def _dedupe(items):
    seen = set()
    ordered = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def _normalize_risk_text(risk):
    raw = str(risk or "").strip().lower()
    normalized = (
        raw.replace("Ã¼", "u")
        .replace("ÅŸ", "s")
        .replace("Ä±", "i")
        .replace("Ã¶", "o")
        .replace("ÄŸ", "g")
        .replace("Ã§", "c")
        .replace("ü", "u")
        .replace("ş", "s")
        .replace("ı", "i")
        .replace("ö", "o")
        .replace("ğ", "g")
        .replace("ç", "c")
    )

    if "yuksek" in normalized or ("yÃ" in raw and "ksek" in normalized):
        return "yuksek"
    if "dusuk" in normalized or ("dÃ" in raw and "uk" in normalized):
        return "dusuk"
    if "orta" in normalized:
        return "orta"
    if "bilinmiyor" in normalized:
        return "bilinmiyor"
    return normalized


def _is_high_risk(risk):
    return _normalize_risk_text(risk) == "yuksek"


def _severity_from_score(score):
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    return "medium"


def _severity_label(severity):
    labels = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
    }
    return labels.get(severity, "Medium")


def _calculate_exploitability(host):
    score = 0
    scenarios = host.get("attack_scenarios", [])
    known_cve_count = host.get("known_cve_count", 0)
    brute_force_risk_count = host.get("brute_force_risk_count", 0)
    general_risk = _normalize_risk_text(host.get("general_risk"))

    score += min(45, sum(item.get("impact_score", 0) * 5 for item in scenarios))
    score += min(20, known_cve_count * 4)
    score += min(15, brute_force_risk_count * 5)

    if general_risk == "yuksek":
        score += 12
    elif general_risk == "orta":
        score += 6

    if host.get("firewall_detected"):
        score -= 5
    if host.get("scan_timed_out"):
        score -= 8

    score = max(0, min(100, score))
    if score >= 80:
        level = "Kritik"
    elif score >= 60:
        level = "Yuksek"
    elif score >= 35:
        level = "Orta"
    else:
        level = "Dusuk"
    return score, level


def _build_red_team_summary(host):
    scenarios = host.get("attack_scenarios", [])
    exploitability_score = host.get("exploitability_score", 0)
    exploitability_level = host.get("exploitability_level", "Dusuk")

    if scenarios:
        top = max(scenarios, key=lambda item: item.get("impact_score", 0))
        return (
            f"En olasi istismar yolu: {top['title']} | "
            f"Istismar Edilebilirlik: {exploitability_level} ({exploitability_score}/100)."
        )

    if host.get("known_cve_count", 0) > 0:
        return f"Bilinen CVE kayitlari nedeniyle hedefte exploit denemesi yapilabilir. Skor: {exploitability_score}/100."
    if host.get("brute_force_risk_count", 0) > 0:
        return f"Uzak erisim servisleri parola saldirilarina acik olabilir. Skor: {exploitability_score}/100."
    if host.get("firewall_detected"):
        return f"Firewall izleri goruluyor; acik servislere odakli sinirli kesif gerekebilir. Skor: {exploitability_score}/100."
    return "Belirgin bir exploit akisi uretilmedi; manuel dogrulama gerekir."


def _build_red_team_highlights(host):
    scenarios = host.get("attack_scenarios", [])
    highlights = []

    if host.get("known_cve_count", 0) > 0:
        highlights.append(f"{host.get('known_cve_count', 0)} CVE eslesmesi")
    if host.get("brute_force_risk_count", 0) > 0:
        highlights.append(f"{host.get('brute_force_risk_count', 0)} brute-force yuzeyi")
    if scenarios:
        top = max(scenarios, key=lambda item: item.get("impact_score", 0))
        highlights.append(f"Oncelikli senaryo: {top['title']}")

    return _dedupe(highlights)[:3]


def _make_action(host, score, category, title, detail):
    severity = _severity_from_score(score)
    return {
        "score": score,
        "severity": severity,
        "severity_label": _severity_label(severity),
        "category": category,
        "title": title,
        "detail": detail,
        "host_ip": host["ip"],
    }


def _collect_priority_actions(host):
    actions = []

    for port in host.get("open_ports_data", []):
        port_id = port.get("port")
        service = port.get("service", "bilinmeyen servis")
        service_version = port.get("service_version", "Bilinmiyor")
        risk = port.get("risk", "")
        recommendation = port.get("recommendation", "")
        cves = port.get("cves", [])

        if cves:
            top_cve = cves[0]
            score = 100 if any("critical" in str(cve.get("severity", "")).lower() for cve in cves) else 92
            actions.append(
                _make_action(
                    host,
                    score,
                    "Yamala",
                    f"{host['ip']} uzerindeki {port_id}/{service} servisini yamala",
                    f"{service_version} icin {top_cve.get('cve_id', 'bilinmeyen CVE')} eslesmesi bulundu.",
                )
            )

        if port_id in HIGH_RISK_PORTS or _normalize_risk_text(risk) == "yuksek":
            actions.append(
                _make_action(
                    host,
                    84,
                    "Kapat/Kisitla",
                    f"{host['ip']} uzerindeki {port_id}/{service} servisini gozden gecir",
                    recommendation or "Servis gereksizse kapatilmali veya yalnizca gerekli kaynaklara acilmalidir.",
                )
            )

        if port_id in BRUTE_FORCE_PORTS:
            actions.append(
                _make_action(
                    host,
                    78,
                    "Erisim Guvenligi",
                    f"{host['ip']} uzerindeki {port_id}/{service} icin erisim korumasi ekle",
                    "VPN, MFA, hesap kilitleme ve izinli IP sinirlamasi uygulanmalidir.",
                )
            )

        if port_id in {139, 445}:
            actions.append(
                _make_action(
                    host,
                    80,
                    "Ag Segmentasyonu",
                    f"{host['ip']} uzerindeki SMB/NetBIOS erisimini sinirla",
                    "Dosya paylasim servisleri yalnizca yerel agdan erisilebilir olmali ve eski protokoller kapatilmalidir.",
                )
            )

    if host.get("firewall_detected"):
        actions.append(
            _make_action(
                host,
                60,
                "Firewall",
                f"{host['ip']} icin firewall kurallarini dogrula",
                "Filtered portlar goruldu; izin verilen servislerin gerekliligi ve kaynak IP kisitlari kontrol edilmelidir.",
            )
        )
    else:
        actions.append(
            _make_action(
                host,
                74,
                "Firewall",
                f"{host['ip']} icin temel firewall politikasi uygula",
                "Host onunde yalnizca gerekli portlari acik birakan bir ACL veya firewall kural seti tanimlanmalidir.",
            )
        )

    if _is_high_risk(host.get("general_risk")):
        actions.append(
            _make_action(
                host,
                76,
                "Segmentasyon",
                f"{host['ip']} hostunu daha dar bir ag segmentine tasi",
                "Yuksek riskli hostlarda yanal hareketi azaltmak icin ag segmentasyonu uygulanmalidir.",
            )
        )

    ordered = sorted(actions, key=lambda item: (-item["score"], item["title"]))
    unique = []
    seen = set()
    for action in ordered:
        key = (action["title"], action["detail"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(action)
    return unique


def _build_blue_team_actions(priority_actions):
    lines = []
    for action in priority_actions[:5]:
        lines.append(f"[{action['severity_label']}] {action['detail']}")
    return _dedupe(lines)


def _build_blue_team_summary(host):
    actions = host.get("priority_actions", [])
    if not actions:
        return "Belirgin aksiyon uretilmedi; manuel dogrulama onerilir."

    critical = sum(1 for item in actions if item.get("severity") == "critical")
    high = sum(1 for item in actions if item.get("severity") == "high")
    medium = sum(1 for item in actions if item.get("severity") == "medium")
    top = actions[0]
    return (
        f"Oncelikli aksiyon: {top['title']} | "
        f"Critical: {critical}, High: {high}, Medium: {medium}."
    )


def _first_entry_vector(host):
    scenarios = host.get("attack_scenarios", [])
    if not scenarios:
        return "Belirgin bir ilk giris vektoru uretilmedi."
    top = max(scenarios, key=lambda item: item.get("impact_score", 0))
    return f"{top['title']} ({top.get('likelihood', 'Orta')} olasilik)"


def _recommended_first_action(host):
    actions = host.get("priority_actions", [])
    if not actions:
        return "Belirgin bir ilk aksiyon uretilmedi."
    top = actions[0]
    return f"[{top.get('severity_label', 'Medium')}] {top['title']}"


def _build_network_priority_plan(host_reports):
    combined = []
    for host in host_reports:
        for action in host.get("priority_actions", []):
            combined.append(dict(action))

    combined.sort(key=lambda item: (-item["score"], item["host_ip"], item["title"]))

    top_plan = []
    for index, action in enumerate(combined[:8], start=1):
        top_plan.append(
            {
                "order": index,
                "host_ip": action["host_ip"],
                "category": action["category"],
                "title": action["title"],
                "detail": action["detail"],
                "score": action["score"],
                "severity": action["severity"],
                "severity_label": action["severity_label"],
            }
        )
    return top_plan


def _summarize_priority_counts(actions):
    return {
        "critical": sum(1 for item in actions if item.get("severity") == "critical"),
        "high": sum(1 for item in actions if item.get("severity") == "high"),
        "medium": sum(1 for item in actions if item.get("severity") == "medium"),
    }


def apply_team_mode_analysis(network_summary, host_reports):
    red_host_count = 0
    exploitability_total = 0
    blue_priority_hosts = 0
    network_priority_actions = []
    network_exploitability_max = None

    for host in host_reports:
        exploitability_score, exploitability_level = _calculate_exploitability(host)
        host["exploitability_score"] = exploitability_score
        host["exploitability_level"] = exploitability_level
        host["red_team_highlights"] = _build_red_team_highlights(host)

        priority_actions = _collect_priority_actions(host)
        host["priority_actions"] = priority_actions
        host["blue_team_actions"] = _build_blue_team_actions(priority_actions)
        host["blue_team_summary"] = _build_blue_team_summary(host)
        host["priority_counts"] = _summarize_priority_counts(priority_actions)
        host["blue_team_priority"] = "Yuksek" if host["priority_counts"]["critical"] or host["priority_counts"]["high"] else "Normal"

        host["red_team_summary"] = _build_red_team_summary(host)
        host["first_entry_vector"] = _first_entry_vector(host)
        host["recommended_first_action"] = _recommended_first_action(host)

        if host.get("attack_scenarios"):
            red_host_count += 1
        if host["blue_team_priority"] == "Yuksek":
            blue_priority_hosts += 1

        exploitability_total += exploitability_score
        network_priority_actions.extend(priority_actions)

        if network_exploitability_max is None or exploitability_score > network_exploitability_max["score"]:
            network_exploitability_max = {
                "ip": host["ip"],
                "score": exploitability_score,
                "level": exploitability_level,
            }

    network_summary["red_team_host_count"] = red_host_count
    network_summary["blue_team_priority_hosts"] = blue_priority_hosts
    network_summary["priority_action_plan"] = _build_network_priority_plan(host_reports)
    network_summary["priority_counts"] = _summarize_priority_counts(network_priority_actions)
    network_summary["average_exploitability_score"] = (
        round(exploitability_total / len(host_reports), 1) if host_reports else 0
    )
    network_summary["max_exploitability"] = network_exploitability_max or {"ip": "Yok", "score": 0, "level": "Dusuk"}
    top_red_host = max(host_reports, key=lambda item: item.get("exploitability_score", 0), default=None)
    top_blue_host = max(
        host_reports,
        key=lambda item: item.get("priority_actions", [{}])[0].get("score", 0) if item.get("priority_actions") else 0,
        default=None,
    )
    network_summary["most_likely_entry_vector"] = (
        f"{top_red_host.get('ip')} | {top_red_host.get('first_entry_vector')}"
        if top_red_host
        else "Belirgin bir giris vektoru uretilmedi."
    )
    network_summary["recommended_first_action"] = (
        f"{top_blue_host.get('ip')} | {top_blue_host.get('recommended_first_action')}"
        if top_blue_host
        else "Belirgin bir ilk aksiyon uretilmedi."
    )

    network_summary["red_team_summary"] = (
        f"{red_host_count} host icin senaryo uretildi. "
        f"En yuksek istismar edilebilirlik: {network_summary['max_exploitability']['ip']} "
        f"({network_summary['max_exploitability']['score']}/100, {network_summary['max_exploitability']['level']})."
    )
    network_summary["blue_team_summary"] = (
        f"Critical: {network_summary['priority_counts']['critical']}, "
        f"High: {network_summary['priority_counts']['high']}, "
        f"Medium: {network_summary['priority_counts']['medium']} aksiyon hazir."
    )
