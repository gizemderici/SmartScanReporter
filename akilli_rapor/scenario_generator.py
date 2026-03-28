def _mitre_mapping_for_scenario(scenario_key):
    mappings = {
        "smb_exploit": [
            {
                "tactic": "Lateral Movement",
                "technique_id": "T1021.002",
                "technique": "SMB/Windows Admin Shares",
            },
            {
                "tactic": "Execution",
                "technique_id": "T1203",
                "technique": "Exploitation for Client Execution",
            },
        ],
        "web_exploit": [
            {
                "tactic": "Initial Access",
                "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application",
            },
            {
                "tactic": "Collection",
                "technique_id": "T1005",
                "technique": "Data from Local System",
            },
        ],
        "brute_force": [
            {
                "tactic": "Credential Access",
                "technique_id": "T1110",
                "technique": "Brute Force",
            },
            {
                "tactic": "Initial Access",
                "technique_id": "T1078",
                "technique": "Valid Accounts",
            },
        ],
        "limited_discovery": [
            {
                "tactic": "Discovery",
                "technique_id": "T1046",
                "technique": "Network Service Discovery",
            },
            {
                "tactic": "Reconnaissance",
                "technique_id": "T1595",
                "technique": "Active Scanning",
            },
        ],
    }
    return mappings.get(scenario_key, [])


def _attach_mitre(scenario, scenario_key):
    scenario["mitre_attack"] = _mitre_mapping_for_scenario(scenario_key)
    return scenario


def generate_attack_scenarios(network_summary, host_reports):
    total_scenarios = 0
    hosts_with_scenarios = 0
    total_impact_score = 0
    mitre_technique_ids = set()

    for host in host_reports:
        scenarios = []
        ports_by_number = {port["port"]: port for port in host["open_ports_data"]}

        smb_port = ports_by_number.get(445)
        if smb_port:
            smb_cves = [cve for cve in smb_port.get("cves", []) if cve.get("cve_id") == "CVE-2017-0144"]
            scenarios.append(
                _attach_mitre(
                    {
                        "title": "SMB Istismar Senaryosu",
                        "steps": [
                            "Port 445 (SMB) acik.",
                            "Yerel agdan veya erisilebilir segmentten SMB servisine baglanti kurulabilir.",
                            "SMB uzerinde bilinen zafiyetler veya yanlis yapilandirmalar kullanilarak EternalBlue benzeri denemeler yapilabilir."
                            if smb_cves
                            else "SMB servisi uzerinden paylasimlar ve kimlik dogrulama yuzeyi hedef alinabilir.",
                        ],
                        "result": "Sistem ele gecirilebilir veya yanal hareket baslatilabilir.",
                        "impact": "Dosya erisimi, kimlik bilgisi toplama ve ag icinde yayilma riski olusur.",
                        "severity": "Kritik",
                        "impact_score": 9,
                    },
                    "smb_exploit",
                )
            )

        web_port = ports_by_number.get(80) or ports_by_number.get(443)
        if web_port and any(cve.get("cve_id") == "CVE-2021-41773" for cve in web_port.get("cves", [])):
            scenarios.append(
                _attach_mitre(
                    {
                        "title": "Web Sunucusu Istismar Senaryosu",
                        "steps": [
                            f"Port {web_port['port']} uzerinde web servisi acik.",
                            f"Tespit edilen surum: {web_port.get('service_version', 'Bilinmiyor')}.",
                            "Path traversal veya benzeri HTTP tabanli aciklardan yararlanilarak hassas dosyalara erisim denenebilir.",
                        ],
                        "result": "Sunucu uzerinde yetkisiz dosya erisimi veya kod calistirma olusabilir.",
                        "impact": "Web sunucusu uzerinden sistem icerigi sizabilir ve servis butunlugu bozulabilir.",
                        "severity": "Yuksek",
                        "impact_score": 8,
                    },
                    "web_exploit",
                )
            )

        brute_force_ports = [port for port in host["open_ports_data"] if port.get("has_brute_force_risk")]
        if brute_force_ports:
            services = ", ".join(f"{port['service']}:{port['port']}" for port in brute_force_ports)
            scenarios.append(
                _attach_mitre(
                    {
                        "title": "Kimlik Bilgisi Zorlama Senaryosu",
                        "steps": [
                            f"Brute-force acisindan hassas servisler acik: {services}.",
                            "Zayif parola veya varsayilan kimlik bilgileri varsa otomatik parola denemeleri yapilabilir.",
                            "Elde edilen hesaplarla uzaktan oturum acilarak kalicilik saglanabilir.",
                        ],
                        "result": "Yetkisiz erisim elde edilebilir.",
                        "impact": "Sunucu yonetimi ele gecirilebilir, veri sizdirma ve yanal hareket mumkun olabilir.",
                        "severity": "Yuksek",
                        "impact_score": 7,
                    },
                    "brute_force",
                )
            )

        if host.get("firewall_detected") and not scenarios:
            scenarios.append(
                _attach_mitre(
                    {
                        "title": "Sinirli Kesif Senaryosu",
                        "steps": [
                            "Bazi portlar filtered durumda gorunuyor.",
                            "Bu durum firewall veya ACL korumasina isaret ediyor.",
                            "Saldirgan acik kalan servisler uzerinden daha sessiz kesif ve kimlik toplama denemeleri yapabilir.",
                        ],
                        "result": "Dogrudan istismar zorlasse da acik kalan servisler hedef olmaya devam eder.",
                        "impact": "Yanlis yapilandirilmis tek bir servis bile saldiri yuzeyi olusturabilir.",
                        "severity": "Orta",
                        "impact_score": 4,
                    },
                    "limited_discovery",
                )
            )

        for scenario in scenarios:
            for mitre_item in scenario.get("mitre_attack", []):
                technique_id = mitre_item.get("technique_id")
                if technique_id:
                    mitre_technique_ids.add(technique_id)

        host["attack_scenarios"] = scenarios
        host["scenario_impact_score"] = sum(item["impact_score"] for item in scenarios)
        host["mitre_technique_count"] = len(
            {item["technique_id"] for scenario in scenarios for item in scenario.get("mitre_attack", [])}
        )
        total_scenarios += len(scenarios)
        total_impact_score += host["scenario_impact_score"]
        if scenarios:
            hosts_with_scenarios += 1

    network_summary["scenario_count"] = total_scenarios
    network_summary["scenario_host_count"] = hosts_with_scenarios
    network_summary["scenario_total_impact_score"] = total_impact_score
    network_summary["mitre_technique_count"] = len(mitre_technique_ids)
    network_summary["mitre_summary"] = (
        f"{len(mitre_technique_ids)} farkli MITRE ATT&CK teknigi ile iliskilendirildi."
        if mitre_technique_ids
        else "MITRE ATT&CK eslesmesi uretilmedi."
    )
