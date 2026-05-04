import html
import os
from datetime import datetime

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


BASE_DIR = os.path.dirname(__file__)
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
HTML_RAPOR_DOSYASI = os.path.join(REPORTS_DIR, "report.html")
TXT_RAPOR_DOSYASI = os.path.join(REPORTS_DIR, "report.txt")
PDF_RAPOR_DOSYASI = os.path.join(REPORTS_DIR, "report.pdf")


def normalize_risk_label(risk):
    normalized = (risk or "").strip().lower()
    normalized = (
        normalized
        .replace("ü", "u")
        .replace("ş", "s")
        .replace("ı", "i")
        .replace("ö", "o")
        .replace("ğ", "g")
        .replace("ç", "c")
        .replace("Ã¼", "u")
        .replace("ÅŸ", "s")
        .replace("Ä±", "i")
        .replace("Ã¶", "o")
        .replace("ÄŸ", "g")
        .replace("Ã§", "c")
    )
    if "yuksek" in normalized:
        return "Yuksek"
    if "orta" in normalized:
        return "Orta"
    if "dusuk" in normalized:
        return "Dusuk"
    if "bilinmiyor" in normalized:
        return "Bilinmiyor"
    mapping = {
        "yüksek": "Yuksek",
        "yuksek": "Yuksek",
        "orta": "Orta",
        "düşük": "Dusuk",
        "dusuk": "Dusuk",
        "bilinmiyor": "Bilinmiyor",
    }
    return mapping.get(normalized, risk or "Bilinmiyor")


def risk_class(risk):
    normalized = normalize_risk_label(risk)
    if normalized == "Yuksek":
        return "high"
    if normalized == "Orta":
        return "medium"
    if normalized == "Dusuk":
        return "low"
    return "unknown"


def mode_label(mode):
    return "Red Team" if mode == "red" else "Blue Team"


def mode_question(mode):
    return "Bu ag nasil hacklenir?" if mode == "red" else "Bu ag nasil korunur?"


def html_escape(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def build_printable_report_html(html_path=HTML_RAPOR_DOSYASI):
    if not os.path.exists(html_path):
        return None

    with open(html_path, "r", encoding="utf-8") as file:
        html = file.read()

    printable_style = """
    <style>
        .pdf-toolbar {
            position: sticky;
            top: 0;
            z-index: 10;
            background: #1f3b5b;
            color: white;
            padding: 12px 16px;
            margin: -30px -30px 20px -30px;
        }
        .pdf-toolbar button {
            padding: 10px 16px;
            border: none;
            border-radius: 6px;
            background: white;
            color: #1f3b5b;
            cursor: pointer;
            font-weight: bold;
        }
        @media print {
            .pdf-toolbar {
                display: none;
            }
            body {
                background: white !important;
                margin: 0;
            }
            .card {
                box-shadow: none !important;
                break-inside: avoid;
            }
        }
    </style>
    """
    toolbar = """
    <div class="pdf-toolbar">
        <button onclick="window.print()">PDF Olarak Kaydet / Yazdir</button>
    </div>
    """
    script = """
    <script>
        window.addEventListener('load', function () {
            setTimeout(function () {
                window.print();
            }, 400);
        });
    </script>
    """

    html = html.replace("</head>", printable_style + "</head>")
    html = html.replace("<body>", "<body>" + toolbar, 1)
    html = html.replace("</body>", script + "</body>")
    return html


def can_generate_pdf():
    return REPORTLAB_AVAILABLE


def build_text_report_lines(network_summary, host_reports, comparison=None, mode="red"):
    report_lines = []
    report_lines.append("#" * 50)
    report_lines.append("GENEL AG OZETI")
    report_lines.append("#" * 50)
    report_lines.append(f"Analiz Modu: {mode_label(mode)}")
    report_lines.append(f"Mod Sorusu: {mode_question(mode)}")
    report_lines.append(f"Toplam Aktif Host Sayisi: {network_summary['total_hosts']}")
    report_lines.append(f"Yuksek Riskli Host Sayisi: {network_summary['high_risk_hosts']}")
    report_lines.append(f"Orta Riskli Host Sayisi: {network_summary['medium_risk_hosts']}")
    report_lines.append(f"Dusuk Riskli Host Sayisi: {network_summary['low_risk_hosts']}")
    report_lines.append(f"Bilinen CVE Bulunan Host Sayisi: {network_summary['hosts_with_known_cves']}")
    report_lines.append(f"Toplam Eslesen CVE Sayisi: {network_summary['total_known_cves']}")
    report_lines.append(f"Firewall Belirtisi Olan Host Sayisi: {network_summary['firewall_detected_hosts']}")
    report_lines.append(f"Toplam Filtered Port Sayisi: {network_summary['total_filtered_ports']}")
    if network_summary.get("timed_out_hosts", 0) > 0:
        report_lines.append(f"Zaman Asimina Ugrayan Host Sayisi: {network_summary.get('timed_out_hosts', 0)}")
    report_lines.append(f"Brute-Force Riski Olan Host Sayisi: {network_summary['brute_force_risk_hosts']}")
    report_lines.append(f"Saldiri Senaryosu Uretilen Host Sayisi: {network_summary['scenario_host_count']}")
    report_lines.append(f"Toplam Saldiri Senaryosu: {network_summary['scenario_count']}")
    report_lines.append(f"Toplam Senaryo Etki Skoru: {network_summary['scenario_total_impact_score']}")
    report_lines.append(f"MITRE ATT&CK Teknik Sayisi: {network_summary.get('mitre_technique_count', 0)}")
    report_lines.append(f"CVE Veri Kaynagi: {network_summary.get('cve_data_source', 'Yerel esleme')}")
    report_lines.append(f"En Riskli Host: {network_summary['most_risky_host']}")
    report_lines.append(
        f"Ortalama Exploitability Skoru: {network_summary.get('average_exploitability_score', 0)}/100"
    )
    report_lines.append(
        "En Yuksek Exploitability: "
        f"{network_summary.get('max_exploitability', {}).get('ip', 'Yok')} | "
        f"{network_summary.get('max_exploitability', {}).get('score', 0)}/100 | "
        f"{network_summary.get('max_exploitability', {}).get('level', 'Dusuk')}"
    )
    report_lines.append(f"En Olasi Giris Vektoru: {network_summary.get('most_likely_entry_vector', '-')}")
    report_lines.append(f"Onerilen Ilk Aksiyon: {network_summary.get('recommended_first_action', '-')}")

    if network_summary.get("nse_finding_count", 0) > 0:
        report_lines.append(f"NSE Script Bulgusu: {network_summary.get('nse_finding_count', 0)}")
        report_lines.append(f"NSE Bulgusu Olan Host Sayisi: {network_summary.get('nse_host_count', 0)}")
        report_lines.append("NSE SCRIPT OZETI")
        for item in network_summary.get("nse_findings", []):
            report_lines.append(
                f"- {item['ip']} | {item['port']}/{item['protocol']} | {item['script_id']} | {item['summary']}"
            )

    if network_summary.get("udp_service_count", 0) > 0:
        report_lines.append(f"UDP Servis Sayisi: {network_summary.get('udp_service_count', 0)}")
        report_lines.append(f"UDP Servisi Olan Host Sayisi: {network_summary.get('udp_host_count', 0)}")
        report_lines.append("UDP SERVIS OZETI")
        for item in network_summary.get("udp_services", []):
            report_lines.append(f"- {item['ip']} | {item['port']}/udp | {item['service']} | Risk: {item['risk']}")

    if mode == "red":
        report_lines.append(f"Red Team Ozet: {network_summary.get('red_team_summary', '-')}")
        report_lines.append(f"MITRE ATT&CK: {network_summary.get('mitre_summary', '-')}")
    else:
        report_lines.append(f"Blue Team Ozet: {network_summary.get('blue_team_summary', '-')}")
        report_lines.append(
            "Aksiyon Seviyeleri: "
            f"Critical {network_summary.get('priority_counts', {}).get('critical', 0)} | "
            f"High {network_summary.get('priority_counts', {}).get('high', 0)} | "
            f"Medium {network_summary.get('priority_counts', {}).get('medium', 0)}"
        )
        if network_summary.get("priority_action_plan"):
            report_lines.append("ONCELIKLENDIRILMIS AKSIYON PLANI")
            for item in network_summary["priority_action_plan"]:
                report_lines.append(
                    f"{item['order']}. [{item.get('severity_label', 'Medium')}] "
                    f"{item['title']} | {item['detail']} | Oncelik Puani: {item['score']}"
                )

    if comparison:
        report_lines.append(f"Onceki Tarama: {comparison.get('previous_scan_time') or 'Onceki kayit yok'}")
        report_lines.append(f"Yeni Acilan Port Sayisi: {comparison['summary']['new_port_count']}")
        report_lines.append(f"Kapanan Port Sayisi: {comparison['summary']['closed_port_count']}")
        report_lines.append(f"Risk Artisi Gorulen Host Sayisi: {comparison['summary']['risk_increase_count']}")

    report_lines.append("")
    report_lines.append("HOST LISTESI")

    for host in network_summary["host_list"]:
        report_lines.append(
            f"- {host['ip']} | OS: {host['detected_os']} | Risk: {host['general_risk']} | "
            f"Acik Port: {host['open_ports']} | Filtered: {host['filtered_ports']} | "
            f"Firewall: {'Evet' if host['firewall_detected'] else 'Hayir'} | "
            f"CVE: {host['known_cve_count']} | Skor: {host['score']}"
        )

    report_lines.append("")

    for host in host_reports:
        report_lines.append("=" * 50)
        report_lines.append(f"Host: {host['ip']}")
        report_lines.append("=" * 50)
        report_lines.append(f"Tespit Edilen Isletim Sistemi: {host['detected_os']}")
        report_lines.append(f"Toplam Acik Port Sayisi: {host['total_open_ports']}")
        report_lines.append(f"Filtered Port Sayisi: {host['total_filtered_ports']}")
        report_lines.append(
            "Firewall Tespiti: "
            + ("Evet, filtered portlar bulundu." if host["firewall_detected"] else "Belirgin firewall gostergesi yok.")
        )
        report_lines.append(f"Brute-Force Riskli Servis Sayisi: {host['brute_force_risk_count']}")
        report_lines.append(f"Saldiri Senaryosu Sayisi: {len(host.get('attack_scenarios', []))}")
        report_lines.append(f"Senaryo Etki Skoru: {host.get('scenario_impact_score', 0)}")
        report_lines.append(
            f"Exploitability Skoru: {host.get('exploitability_score', 0)}/100 | "
            f"Seviye: {host.get('exploitability_level', 'Dusuk')}"
        )
        report_lines.append(f"Genel Risk Seviyesi: {host['general_risk']}")
        report_lines.append(f"Risk Skoru: {host['host_score']}")
        if host.get("scan_timed_out"):
            report_lines.append(
                "Uyari: Host cevap verdi ancak detayli tarama zaman asimina ugradi. "
                "Bu nedenle port/servis bilgileri eksik veya bos olabilir."
            )
        report_lines.append("")

        if mode == "red":
            report_lines.append(f"Red Team Ozeti: {host.get('red_team_summary', '-')}")
            if host.get("red_team_highlights"):
                report_lines.append("RED TEAM ONE CIKANLAR")
                for item in host["red_team_highlights"]:
                    report_lines.append(f"- {item}")
            if host.get("attack_scenarios"):
                report_lines.append("SALDIRI SENARYOSU SIMULASYONU")
                for scenario in host["attack_scenarios"]:
                    report_lines.append(f"Senaryo: {scenario['title']}")
                    report_lines.append(f"Siddet: {scenario['severity']} | Etki Skoru: {scenario['impact_score']}/10")
                    for index, step in enumerate(scenario["steps"], start=1):
                        report_lines.append(f"{index}. {step}")
                    report_lines.append(f"Sonuc: {scenario['result']}")
                    report_lines.append(f"Etki: {scenario['impact']}")
                    if scenario.get("mitre_attack"):
                        report_lines.append("MITRE ATT&CK ESLESMELERI")
                        for item in scenario["mitre_attack"]:
                            report_lines.append(f"- {item['tactic']} | {item['technique_id']} | {item['technique']}")
                    report_lines.append("")
        else:
            report_lines.append(f"Blue Team Onceligi: {host.get('blue_team_priority', 'Normal')}")
            report_lines.append(
                "Aksiyon Seviyeleri: "
                f"Critical {host.get('priority_counts', {}).get('critical', 0)} | "
                f"High {host.get('priority_counts', {}).get('high', 0)} | "
                f"Medium {host.get('priority_counts', {}).get('medium', 0)}"
            )
            report_lines.append(f"Blue Team Ozeti: {host.get('blue_team_summary', '-')}")
            if host.get("priority_actions"):
                report_lines.append("HOST ICIN SIRALI AKSIYONLAR")
                for index, item in enumerate(host["priority_actions"][:4], start=1):
                    report_lines.append(
                        f"{index}. [{item.get('severity_label', 'Medium')}] "
                        f"{item['title']} | {item['detail']} | Oncelik Puani: {item['score']}"
                    )
            report_lines.append("SAVUNMA ONERILERI")
            for action in host.get("blue_team_actions", []):
                report_lines.append(f"- {action}")
            report_lines.append("")

        report_lines.append("ACIK PORTLAR VE ANALIZ")
        for port in host["open_ports_data"]:
            report_lines.append("")
            report_lines.append(f"Port: {port['port']}/{port['protocol']}")
            report_lines.append(f"Servis: {port['service']}")
            report_lines.append(f"Surum Tespiti: {port['service_version']}")
            report_lines.append(f"Kategori: {port['category']}")
            report_lines.append(f"Risk: {port['risk']}")
            report_lines.append(f"OS Etkisi: {port['os_risk_note']}")
            report_lines.append(f"Brute-Force Riski: {port['brute_force_note']}")
            if port.get("nse_findings"):
                report_lines.append("NSE Script Bulgulari:")
                for finding in port["nse_findings"]:
                    report_lines.append(f"- {finding['id']}: {finding['summary']}")
                    if finding.get("output"):
                        report_lines.append(f"  Cikti: {finding['output']}")
            if port["cves"]:
                for cve in port["cves"]:
                    report_lines.append(
                        f"CVE: {cve['cve_id']} - {cve['title']} | "
                        f"Kaynak: {cve.get('source', 'Yerel esleme')} | "
                        f"Siddet: {cve.get('severity', 'Bilinmiyor')} | "
                        f"Eslesme Nedeni: {cve.get('match_reason', 'Kural eslesmesi bulundu.')} | "
                        f"Aciklama: {cve['description']}"
                    )
            else:
                report_lines.append("CVE: Bilinen eslesme yok")
            report_lines.append(f"Oneri: {port['recommendation']}")

        report_lines.append("")

    return report_lines


def generate_pdf_report(network_summary, host_reports, comparison=None, mode="red", pdf_path=PDF_RAPOR_DOSYASI):
    if not REPORTLAB_AVAILABLE:
        return False

    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)
    report_lines = build_text_report_lines(network_summary, host_reports, comparison, mode=mode)

    pdf = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    x_margin = 40
    y = height - 40
    line_height = 14

    pdf.setTitle("Ag Tarama Raporu")
    pdf.setFont("Helvetica", 10)

    for line in report_lines:
        safe_line = line.encode("latin-1", "replace").decode("latin-1")
        pdf.drawString(x_margin, y, safe_line[:120])
        y -= line_height
        if y <= 40:
            pdf.showPage()
            pdf.setFont("Helvetica", 10)
            y = height - 40

    pdf.save()
    return True


def generate_html_report(
    network_summary,
    host_reports,
    comparison=None,
    mode="red",
    html_path=HTML_RAPOR_DOSYASI,
    risk_chart_url="/static/risk_chart.png",
    os_chart_url="/static/os_distribution.png",
    topology_chart_url="/static/network_topology.png",
):
    os.makedirs(os.path.dirname(html_path), exist_ok=True)
    generated_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Ag Tarama Raporu</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 30px;
            background-color: #f4f6f8;
            color: #222;
        }}
        h1, h2, h3 {{
            color: #1f3b5b;
        }}
        .card {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
            vertical-align: top;
        }}
        th {{
            background-color: #e9eef5;
        }}
        .high {{
            color: #b00020;
            font-weight: bold;
        }}
        .medium {{
            color: #c77700;
            font-weight: bold;
        }}
        .low {{
            color: #1a7f37;
            font-weight: bold;
        }}
        .unknown {{
            color: #555;
            font-weight: bold;
        }}
        .state-pill {{
            display: inline-block;
            padding: 6px 10px;
            border-radius: 999px;
            border: 1px solid #d7deea;
            font-size: 0.82rem;
            font-weight: bold;
        }}
        .state-open {{
            color: #1a7f37;
            background: rgba(26, 127, 55, 0.12);
            border-color: rgba(26, 127, 55, 0.24);
        }}
        .state-filtered {{
            color: #c77700;
            background: rgba(199, 119, 0, 0.12);
            border-color: rgba(199, 119, 0, 0.22);
        }}
        .state-closed {{
            color: #b00020;
            background: rgba(176, 0, 32, 0.1);
            border-color: rgba(176, 0, 32, 0.18);
        }}
        .cve-list, .action-list {{
            margin: 0;
            padding-left: 18px;
        }}
        .cve-list li, .action-list li {{
            margin-bottom: 6px;
        }}
        .mode-card {{
            border-left: 6px solid {'#d9534f' if mode == 'red' else '#2563eb'};
        }}
    </style>
</head>
<body>
    <div style="text-align: center; background: linear-gradient(135deg, #1f3b5b, #2563eb); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px;">
        <h1 style="margin: 0; font-size: 2.5em;">Akilli Ag Tarama Raporlama Sistemi</h1>
        <p style="margin: 10px 0 0 0; font-size: 1.1em; opacity: 0.9;">Guvenlik analizi ve raporlama icin kapsamli cozum</p>
        <p style="margin: 10px 0 0 0; font-size: 1.1em; opacity: 0.9;">Rapor Olusturulma Tarihi: {generated_at} | Mod: {mode_label(mode)}</p>
    </div>

    <div class="card">
        <h2>Rapor Hakkinda</h2>
        <p>Bu rapor, ag tarama sonuclarini detayli olarak analiz eder ve guvenlik ekipleri icin yorumlanabilir bir cikti uretir.</p>
        <p><strong>Tarama Metodolojisi:</strong> Nmap port taramasi, servis surum tespiti ve isletim sistemi fingerprinting</p>
        <p><strong>Risk Degerlendirme:</strong> Acik portlar, servis surumleri ve bilinen CVE kayitlari baz alinarak yapilir.</p>
        <p><strong>Analiz Modlari:</strong> Red Team (saldirgan perspektifi) ve Blue Team (savunma perspektifi)</p>
    </div>

    <div class="card">
        <h2>Genel Ag Ozeti</h2>
        <p><strong>Analiz Modu:</strong> {mode_label(mode)}</p>
        <p><strong>Mod Sorusu:</strong> {mode_question(mode)}</p>
        <p><strong>Toplam Aktif Host Sayisi:</strong> {network_summary['total_hosts']}</p>
        <p><strong>Yuksek Riskli Host Sayisi:</strong> {network_summary['high_risk_hosts']}</p>
        <p><strong>Orta Riskli Host Sayisi:</strong> {network_summary['medium_risk_hosts']}</p>
        <p><strong>Dusuk Riskli Host Sayisi:</strong> {network_summary['low_risk_hosts']}</p>
        <p><strong>Bilinen CVE Bulunan Host Sayisi:</strong> {network_summary['hosts_with_known_cves']}</p>
        <p><strong>Toplam Eslesen CVE Sayisi:</strong> {network_summary['total_known_cves']}</p>
        <p><strong>Firewall Belirtisi Olan Host Sayisi:</strong> {network_summary['firewall_detected_hosts']}</p>
        <p><strong>Toplam Filtered Port Sayisi:</strong> {network_summary['total_filtered_ports']}</p>
        {f"<p><strong>Zaman Asimina Ugrayan Host Sayisi:</strong> {network_summary.get('timed_out_hosts', 0)}</p>" if network_summary.get('timed_out_hosts', 0) > 0 else ""}
        <p><strong>Brute-Force Riski Olan Host Sayisi:</strong> {network_summary['brute_force_risk_hosts']}</p>
        <p><strong>Saldiri Senaryosu Uretilen Host Sayisi:</strong> {network_summary['scenario_host_count']}</p>
        <p><strong>Toplam Saldiri Senaryosu:</strong> {network_summary['scenario_count']}</p>
        <p><strong>Toplam Senaryo Etki Skoru:</strong> {network_summary['scenario_total_impact_score']}</p>
        <p><strong>MITRE ATT&CK Teknik Sayisi:</strong> {network_summary.get('mitre_technique_count', 0)}</p>
        <p><strong>CVE Veri Kaynagi:</strong> {network_summary.get('cve_data_source', 'Yerel esleme')}</p>
        <p><strong>En Riskli Host:</strong> {network_summary['most_risky_host']}</p>
        <p><strong>Ortalama Exploitability Skoru:</strong> {network_summary.get('average_exploitability_score', 0)}/100</p>
        <p><strong>En Yuksek Exploitability:</strong> {network_summary.get('max_exploitability', {}).get('ip', 'Yok')} | {network_summary.get('max_exploitability', {}).get('score', 0)}/100 | {network_summary.get('max_exploitability', {}).get('level', 'Dusuk')}</p>
    </div>
    """

    if network_summary.get("udp_service_count", 0) > 0:
        html += f"""
    <div class="card">
        <h2>UDP Servis Ozeti</h2>
        <p><strong>UDP Servis Sayisi:</strong> {network_summary.get('udp_service_count', 0)}</p>
        <p><strong>UDP Servisi Olan Host Sayisi:</strong> {network_summary.get('udp_host_count', 0)}</p>
        <ul class="action-list">
            {''.join(f"<li><strong>{html_escape(item['ip'])}</strong> - {item['port']}/udp - {html_escape(item['service'])} (<span class='{risk_class(item['risk'])}'>{html_escape(item['risk'])}</span>)</li>" for item in network_summary.get('udp_services', []))}
        </ul>
    </div>
        """

    if network_summary.get("nse_finding_count", 0) > 0:
        html += f"""
    <div class="card">
        <h2>NSE Script Bulgulari</h2>
        <p><strong>Toplam NSE Bulgusu:</strong> {network_summary.get('nse_finding_count', 0)}</p>
        <p><strong>NSE Bulgusu Olan Host Sayisi:</strong> {network_summary.get('nse_host_count', 0)}</p>
        <ul class="action-list">
            {''.join(f"<li><strong>{html_escape(item['ip'])}</strong> - {item['port']}/{html_escape(item['protocol'])} - {html_escape(item['summary'])} <small>({html_escape(item['script_id'])})</small></li>" for item in network_summary.get('nse_findings', []))}
        </ul>
    </div>
        """

    html += f"""
    <div class="card mode-card">
        <h2>{mode_label(mode)} Modu</h2>
        <p><strong>Soru:</strong> {mode_question(mode)}</p>
        <p>{html_escape(network_summary.get('red_team_summary' if mode == 'red' else 'blue_team_summary', '-'))}</p>
        <p><strong>MITRE ATT&CK:</strong> {html_escape(network_summary.get('mitre_summary', '-'))}</p>
        {f"<p><strong>Aksiyon Seviyeleri:</strong> Critical {network_summary.get('priority_counts', {}).get('critical', 0)} | High {network_summary.get('priority_counts', {}).get('high', 0)} | Medium {network_summary.get('priority_counts', {}).get('medium', 0)}</p>" if mode == 'blue' else ""}
    </div>

    <div class="card">
        <h2>Host Listesi</h2>
        <table>
            <tr>
                <th>IP</th>
                <th>Isletim Sistemi</th>
                <th>Genel Risk</th>
                <th>Acik Port Sayisi</th>
                <th>Filtered</th>
                <th>Firewall</th>
                <th>CVE Sayisi</th>
                <th>Risk Skoru</th>
            </tr>
    """

    for host in network_summary["host_list"]:
        html += f"""
            <tr>
                <td>{html_escape(host['ip'])}</td>
                <td>{html_escape(host['detected_os'])}</td>
                <td class="{risk_class(host['general_risk'])}">{host['general_risk']}</td>
                <td>{host['open_ports']}</td>
                <td>{host['filtered_ports']}</td>
                <td>{"Evet" if host['firewall_detected'] else "Hayir"}</td>
                <td>{host['known_cve_count']}</td>
                <td>{host['score']}</td>
            </tr>
        """

    html += """
        </table>
    </div>
    """

    html += f"""
    <div class="card">
        <h2>Grafiksel Analiz ve Aciklamalar</h2>
        <p>Bu bolumde ag tarama sonuclarinin gorsel temsilleri ve kisa aciklamalari yer alir.</p>

        <h3>Risk Dagilimi Grafigi</h3>
        <p>Hostlarin risk seviyelerine gore dagilimini gosterir.</p>
        <img src="{risk_chart_url}" alt="Risk Dagilimi Grafigi" style="max-width: 100%; height: auto; border: 1px solid #ddd; border-radius: 8px;">

        <h3>Isletim Sistemi Dagilimi</h3>
        <p>Ortamda tespit edilen platformlarin genel dagilimini gosterir.</p>
        <img src="{os_chart_url}" alt="OS Dagilim Grafigi" style="max-width: 100%; height: auto; border: 1px solid #ddd; border-radius: 8px;">

        <h3>Ag Topolojisi</h3>
        <p>Tarayan sistem, hedef ag ve bulunan hostlar arasindaki baglantilari ozetler.</p>
        <img src="{topology_chart_url}" alt="Ag Topolojisi" style="max-width: 100%; height: auto; border: 1px solid #ddd; border-radius: 8px;">

        <div style="background: #e9eef5; padding: 15px; border-radius: 8px; margin-top: 20px;">
            <h4>Renk Kodlamasi</h4>
            <ul>
                <li><span style="color: #d9534f; font-weight: bold;">Kirmizi:</span> Yuksek risk</li>
                <li><span style="color: #f0ad4e; font-weight: bold;">Turuncu:</span> Orta risk</li>
                <li><span style="color: #5cb85c; font-weight: bold;">Yesil:</span> Dusuk risk</li>
                <li><span style="color: #94a3b8; font-weight: bold;">Gri:</span> Bilinmiyor</li>
            </ul>
        </div>
    </div>
    """

    if mode == "blue" and network_summary.get("priority_action_plan"):
        html += """
        <div class="card">
            <h2>Onceliklendirilmis Aksiyon Plani</h2>
            <ol>
        """
        for item in network_summary["priority_action_plan"]:
            html += (
                f"<li><strong>{html_escape(item['title'])}</strong><br>"
                f"<small>{html_escape(item['detail'])} | Oncelik Puani: {item['score']}</small></li>"
            )
        html += """
            </ol>
        </div>
        """

    if comparison:
        html += f"""
        <div class="card">
            <h2>Zaman Karsilastirmasi</h2>
            <p><strong>Onceki Tarama:</strong> {comparison.get('previous_scan_time') or 'Onceki kayit yok'}</p>
            <p><strong>Yeni Acilan Port Sayisi:</strong> {comparison['summary']['new_port_count']}</p>
            <p><strong>Kapanan Port Sayisi:</strong> {comparison['summary']['closed_port_count']}</p>
            <p><strong>Risk Artisi Gorulen Host Sayisi:</strong> {comparison['summary']['risk_increase_count']}</p>
        </div>
        """

    for host in host_reports:
        html += f"""
        <div class="card">
            <h2>Host Detayli Analizi: {html_escape(host['ip'])}</h2>
            <p>Bu bolumde {html_escape(host['ip'])} IP adresli host icin detayli guvenlik analizi yer almaktadir.</p>

            <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                <h3>Host Genel Bilgileri</h3>
                <p><strong>Tespit Edilen Isletim Sistemi:</strong> {html_escape(host['detected_os'])}</p>
                <p><strong>Toplam Acik Port Sayisi:</strong> {host['total_open_ports']}</p>
                <p><strong>Filtered Port Sayisi:</strong> {host['total_filtered_ports']}</p>
                <p><strong>Firewall Tespiti:</strong> {"Evet, filtered portlar bulundu." if host['firewall_detected'] else "Belirgin firewall gostergesi yok."}</p>
                <p><strong>Brute-Force Riskli Servis Sayisi:</strong> {host['brute_force_risk_count']}</p>
                <p><strong>Exploitability:</strong> {host.get('exploitability_score', 0)}/100 ({host.get('exploitability_level', 'Dusuk')})</p>
                <p><strong>Genel Risk Seviyesi:</strong> <span class="{risk_class(host['general_risk'])}">{host['general_risk']}</span></p>
                {"<p><strong>Uyari:</strong> Host cevap verdi ancak detayli tarama zaman asimina ugradi. Bu nedenle port ve servis sonuclari eksik ya da bos olabilir.</p>" if host.get('scan_timed_out') else ""}
            </div>
        """

        if mode == "red":
            html += f"<p><strong>Red Team Ozeti:</strong> {html_escape(host.get('red_team_summary', '-'))}</p>"
            if host.get("red_team_highlights"):
                html += "<h3>One Cikanlar</h3><ul class=\"action-list\">"
                for item in host.get("red_team_highlights", []):
                    html += f"<li>{html_escape(item)}</li>"
                html += "</ul>"
            if host.get("attack_scenarios"):
                html += "<h3>Saldiri Senaryosu Simulasyonu</h3>"
                for scenario in host["attack_scenarios"]:
                    html += f"""
                    <div style="margin-bottom: 16px; padding: 14px; border: 1px solid #ddd; border-radius: 8px; background: #fef2f2;">
                        <p><strong>Senaryo Basligi:</strong> {html_escape(scenario['title'])}</p>
                        <p><strong>Siddet Seviyesi:</strong> {html_escape(scenario['severity'])} | <strong>Etki Skoru:</strong> {scenario['impact_score']}/10</p>
                        <p><strong>Saldiri Adimlari:</strong></p>
                        <ol>
                    """
                    for step in scenario["steps"]:
                        html += f"<li>{html_escape(step)}</li>"
                    html += f"""
                        </ol>
                        <p><strong>Beklenen Sonuc:</strong> {html_escape(scenario['result'])}</p>
                        <p><strong>Potansiyel Etki:</strong> {html_escape(scenario['impact'])}</p>
                    """
                    if scenario.get("mitre_attack"):
                        html += "<p><strong>MITRE ATT&CK Eslesmeleri:</strong></p><ul class=\"action-list\">"
                        for item in scenario["mitre_attack"]:
                            html += (
                                f"<li><strong>{html_escape(item['tactic'])}</strong> - "
                                f"{html_escape(item['technique_id'])}: {html_escape(item['technique'])}</li>"
                            )
                        html += "</ul>"
                    html += "</div>"
        else:
            html += f"<p><strong>Blue Team Onceligi:</strong> {html_escape(host.get('blue_team_priority', 'Normal'))}</p>"
            html += f"<p><strong>Blue Team Ozeti:</strong> {html_escape(host.get('blue_team_summary', '-'))}</p>"
            html += (
                "<p><strong>Aksiyon Seviyeleri:</strong> "
                f"Critical {host.get('priority_counts', {}).get('critical', 0)} | "
                f"High {host.get('priority_counts', {}).get('high', 0)} | "
                f"Medium {host.get('priority_counts', {}).get('medium', 0)}</p>"
            )
            if host.get("priority_actions"):
                html += "<h3>Host Icin Sirali Aksiyonlar</h3><ol>"
                for item in host.get("priority_actions", [])[:4]:
                    html += (
                        f"<li><strong>{html_escape(item['title'])}</strong><br>"
                        f"<small>{html_escape(item.get('severity_label', 'Medium'))} | "
                        f"{html_escape(item['detail'])} | Oncelik Puani: {item['score']}</small></li>"
                    )
                html += "</ol>"
            html += "<h3>Savunma Onerileri</h3><ul class=\"action-list\">"
            for action in host.get("blue_team_actions", []):
                html += f"<li>{html_escape(action)}</li>"
            html += "</ul>"

        html += """
            <h3>Acik Portlar ve Guvenlik Analizi</h3>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Protokol</th>
                    <th>Durum</th>
                    <th>Durum Aciklamasi</th>
                    <th>Servis</th>
                    <th>Surum Tespiti</th>
                    <th>Kategori</th>
                    <th>Risk</th>
                    <th>OS Etkisi</th>
                    <th>Brute-Force Riski</th>
                    <th>NSE Script</th>
                    <th>Bilinen CVE</th>
                    <th>Oneri</th>
                </tr>
        """

        for port in host.get("all_ports_data", host["open_ports_data"]):
            cve_html = "Bilinen eslesme yok"
            nse_html = "Script bulgusu yok"
            state_class = f"state-{port.get('state', '').lower()}"

            if port.get("nse_findings"):
                nse_html = "<ul class=\"cve-list\">"
                for finding in port["nse_findings"]:
                    nse_html += (
                        f"<li><strong>{html_escape(finding['id'])}</strong> - "
                        f"{html_escape(finding['summary'])}"
                    )
                    if finding.get("output"):
                        nse_html += f"<br><small>{html_escape(finding['output'])}</small>"
                    nse_html += "</li>"
                nse_html += "</ul>"

            if port["cves"]:
                cve_html = "<ul class=\"cve-list\">"
                for cve in port["cves"]:
                    cve_html += (
                        f"<li><strong>{html_escape(cve['cve_id'])}</strong> - {html_escape(cve['title'])}<br>"
                        f"<small>Kaynak: {html_escape(cve.get('source', 'Yerel esleme'))} | "
                        f"Siddet: {html_escape(cve.get('severity', 'Bilinmiyor'))}</small><br>"
                        f"<small>Eslesme Nedeni: {html_escape(cve.get('match_reason', 'Kural eslesmesi bulundu.'))}</small><br>"
                        f"<small>{html_escape(cve['description'])}</small></li>"
                    )
                cve_html += "</ul>"

            html += f"""
                <tr>
                    <td>{port['port']}</td>
                    <td>{html_escape(port['protocol'])}</td>
                    <td><span class="state-pill {state_class}">{port.get('state', 'unknown').capitalize()}</span></td>
                    <td>{html_escape(port.get('state_explanation', '-'))}</td>
                    <td>{html_escape(port['service'])}</td>
                    <td>{html_escape(port['service_version'])}</td>
                    <td>{html_escape(port['category'])}</td>
                    <td class="{risk_class(port['risk'])}">{port['risk']}</td>
                    <td>{html_escape(port['os_risk_note'])}</td>
                    <td>{html_escape(port['brute_force_note'])}</td>
                    <td>{nse_html}</td>
                    <td>{cve_html}</td>
                    <td>{html_escape(port['recommendation'])}</td>
                </tr>
            """

        html += """
            </table>
        </div>
        """

    html += """
    <div class="card" style="text-align: center; background: #e9eef5; border-top: 4px solid #1f3b5b;">
        <h2>Rapor Tamamlandi</h2>
        <p>Bu rapor Akilli Ag Tarama Raporlama Sistemi tarafindan otomatik olarak olusturulmustur.</p>
        <p><strong>Onemli Not:</strong> Bu rapor guvenlik degerlendirmesi icin bir aractir. Profesyonel destek gereken senaryolarda uzman dogrulamasi onerilir.</p>
    </div>
</body>
</html>
    """

    with open(html_path, "w", encoding="utf-8") as file:
        file.write(html)


def generate_text_report(network_summary, host_reports, comparison=None, mode="red", txt_path=TXT_RAPOR_DOSYASI):
    os.makedirs(os.path.dirname(txt_path), exist_ok=True)
    report_lines = build_text_report_lines(network_summary, host_reports, comparison, mode=mode)

    with open(txt_path, "w", encoding="utf-8") as file:
        for line in report_lines:
            file.write(line + "\n")


def generate_reports(
    network_summary,
    host_reports,
    comparison=None,
    mode="red",
    html_path=HTML_RAPOR_DOSYASI,
    txt_path=TXT_RAPOR_DOSYASI,
    pdf_path=PDF_RAPOR_DOSYASI,
    risk_chart_url="/static/risk_chart.png",
    os_chart_url="/static/os_distribution.png",
    topology_chart_url="/static/network_topology.png",
):
    generate_html_report(
        network_summary,
        host_reports,
        comparison,
        mode=mode,
        html_path=html_path,
        risk_chart_url=risk_chart_url,
        os_chart_url=os_chart_url,
        topology_chart_url=topology_chart_url,
    )
    generate_text_report(network_summary, host_reports, comparison, mode=mode, txt_path=txt_path)
    generate_pdf_report(network_summary, host_reports, comparison, mode=mode, pdf_path=pdf_path)
