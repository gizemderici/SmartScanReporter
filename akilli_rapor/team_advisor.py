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


def _is_high_risk(risk):
    normalized = (risk or "").lower()
    return "yüksek" in normalized or "yÃ¼ksek" in normalized or "yuksek" in normalized


def _build_red_team_summary(host):
    scenarios = host.get("attack_scenarios", [])
    if scenarios:
        top = max(scenarios, key=lambda item: item.get("impact_score", 0))
        return (
            f"En olasi istismar yolu: {top['title']} "
            f"({top.get('severity', 'Bilinmiyor')} / {top.get('impact_score', 0)}/10)."
        )

    if host.get("known_cve_count", 0) > 0:
        return "Bilinen CVE kayitlari nedeniyle hedefte exploit denemesi yapilabilir."
    if host.get("brute_force_risk_count", 0) > 0:
        return "Uzak erisim servisleri brute-force veya parola tahmin saldirilarina acik olabilir."
    if host.get("firewall_detected"):
        return "Firewall izleri goruluyor; saldirgan once acik servislere odaklanip sinirli kesif yapabilir."
    return "Belirgin bir exploit akisi uretilmedi; manuel dogrulama gerekir."


def _build_blue_team_actions(host):
    actions = []
    open_ports = host.get("open_ports_data", [])

    if host.get("known_cve_count", 0) > 0:
        actions.append("Tespit edilen servisler icin yamalari ve guvenlik guncellemelerini oncelikli uygulayin.")

    if host.get("brute_force_risk_count", 0) > 0:
        actions.append("SSH, FTP ve RDP gibi uzak erisim servislerinde MFA, hesap kilitleme ve guclu parola politikasi uygulayin.")

    if host.get("firewall_detected"):
        actions.append("Mevcut firewall kurallarini gozden gecirin; sadece gerekli portlari izinli birakip kaynak IP bazli sinirlama ekleyin.")
    else:
        actions.append("Host onunde firewall veya ACL kullanarak yalnizca gerekli servisleri acik birakin.")

    if _is_high_risk(host.get("general_risk")):
        actions.append("Bu host icin segmentasyon uygulayin ve gerekmedikce internetten dogrudan erisimi kapatin.")

    for port in open_ports:
        port_id = port.get("port")
        service = port.get("service", "bilinmeyen servis")
        recommendation = port.get("recommendation")
        if recommendation:
            actions.append(recommendation)
        if port_id in {21, 22, 3389}:
            actions.append(f"{port_id}/{service} servisini VPN arkasi veya izinli IP listesi ile sinirlandirin.")
        if port_id in {139, 445}:
            actions.append("SMB/NetBIOS servislerini yerel ag ile sinirlandirin ve eski protokolleri kapatin.")
        if port_id in {80, 443} and port.get("cves"):
            actions.append("Web servisi surumunu guncelleyip WAF veya ters proxy ile koruma ekleyin.")
        if port.get("risk") == "Yüksek":
            actions.append(f"{port_id}/{service} icin servis gerekliligini dogrulayin; gereksizse kapatin.")

    return _dedupe(actions)


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
            score = 100 if any(
                "critical" in str(cve.get("severity", "")).lower() for cve in cves
            ) else 90
            actions.append(
                {
                    "score": score,
                    "category": "Yamala",
                    "title": f"{host['ip']} uzerindeki {port_id}/{service} servisini yamala",
                    "detail": f"{service_version} icin {top_cve.get('cve_id', 'bilinmeyen CVE')} eslesmesi bulundu.",
                }
            )

        if port_id in HIGH_RISK_PORTS or "yüksek" in risk.lower() or "yuksek" in risk.lower():
            actions.append(
                {
                    "score": 85,
                    "category": "Kapat/Kisitla",
                    "title": f"{host['ip']} uzerindeki {port_id}/{service} servisini gozden gecir",
                    "detail": recommendation or "Servis gereksizse kapatilmali veya yalnizca gerekli kaynaklara acilmalidir.",
                }
            )

        if port_id in BRUTE_FORCE_PORTS:
            actions.append(
                {
                    "score": 80,
                    "category": "Erisim Guvenligi",
                    "title": f"{host['ip']} uzerindeki {port_id}/{service} icin erisim korumasi ekle",
                    "detail": "VPN, MFA, hesap kilitleme ve izinli IP sinirlamasi uygulanmalidir.",
                }
            )

        if port_id in {139, 445}:
            actions.append(
                {
                    "score": 82,
                    "category": "Ag Segmentasyonu",
                    "title": f"{host['ip']} uzerindeki SMB/NetBIOS erisimini sinirla",
                    "detail": "Dosya paylasim servisleri yalnizca yerel agdan erisilebilir olmali ve eski protokoller kapatilmalidir.",
                }
            )

    if host.get("firewall_detected"):
        actions.append(
            {
                "score": 55,
                "category": "Firewall",
                "title": f"{host['ip']} icin firewall kurallarini dogrula",
                "detail": "Filtered portlar goruldu; izin verilen servislerin gerekliligi ve kaynak IP kisitlari kontrol edilmelidir.",
            }
        )
    else:
        actions.append(
            {
                "score": 70,
                "category": "Firewall",
                "title": f"{host['ip']} icin temel firewall politikasi uygula",
                "detail": "Host onunde yalnizca gerekli portlari acik birakan bir ACL veya firewall kural seti tanimlanmalidir.",
            }
        )

    if _is_high_risk(host.get("general_risk")):
        actions.append(
            {
                "score": 75,
                "category": "Segmentasyon",
                "title": f"{host['ip']} hostunu daha dar bir ag segmentine tasi",
                "detail": "Yuksek riskli hostlarda yanal hareketi azaltmak icin ag segmentasyonu uygulanmalidir.",
            }
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


def _build_network_priority_plan(host_reports):
    combined = []
    for host in host_reports:
        for action in host.get("priority_actions", []):
            item = dict(action)
            item["host_ip"] = host["ip"]
            combined.append(item)

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
            }
        )
    return top_plan


def apply_team_mode_analysis(network_summary, host_reports):
    red_host_count = 0
    blue_priority_hosts = 0

    for host in host_reports:
        red_summary = _build_red_team_summary(host)
        blue_actions = _build_blue_team_actions(host)
        priority_actions = _collect_priority_actions(host)
        host["red_team_summary"] = red_summary
        host["blue_team_actions"] = blue_actions
        host["priority_actions"] = priority_actions
        host["blue_team_priority"] = "Yuksek" if _is_high_risk(host.get("general_risk")) else "Normal"

        if host.get("attack_scenarios"):
            red_host_count += 1
        if host["blue_team_priority"] == "Yuksek":
            blue_priority_hosts += 1

    network_summary["red_team_host_count"] = red_host_count
    network_summary["blue_team_priority_hosts"] = blue_priority_hosts
    network_summary["priority_action_plan"] = _build_network_priority_plan(host_reports)
    network_summary["red_team_summary"] = (
        f"{red_host_count} host icin saldiri akisi uretildi; en riskli hostlar once exploit ve parola saldirisi adayi."
    )
    network_summary["blue_team_summary"] = (
        f"{blue_priority_hosts} host savunma acisindan oncelikli; yamalama, firewall kisitlamasi ve servis kapatma onerileri hazir."
    )
