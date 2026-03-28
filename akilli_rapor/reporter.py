import os

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


def risk_class(risk):
    if risk == "Yüksek":
        return "high"
    if risk == "Orta":
        return "medium"
    if risk == "Düşük":
        return "low"
    return "unknown"


def mode_label(mode):
    return "Red Team" if mode == "red" else "Blue Team"


def mode_question(mode):
    return "Bu ag nasil hacklenir?" if mode == "red" else "Bu ag nasil korunur?"


def build_printable_report_html():
    if not os.path.exists(HTML_RAPOR_DOSYASI):
        return None

    with open(HTML_RAPOR_DOSYASI, "r", encoding="utf-8") as file:
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
    report_lines.append(f"Brute-Force Riski Olan Host Sayisi: {network_summary['brute_force_risk_hosts']}")
    report_lines.append(f"Saldiri Senaryosu Uretilen Host Sayisi: {network_summary['scenario_host_count']}")
    report_lines.append(f"Toplam Saldiri Senaryosu: {network_summary['scenario_count']}")
    report_lines.append(f"Toplam Senaryo Etki Skoru: {network_summary['scenario_total_impact_score']}")
    report_lines.append(f"MITRE ATT&CK Teknik Sayisi: {network_summary.get('mitre_technique_count', 0)}")
    report_lines.append(f"CVE Veri Kaynagi: {network_summary.get('cve_data_source', 'Yerel esleme')}")
    report_lines.append(f"En Riskli Host: {network_summary['most_risky_host']}")
    if mode == "red":
        report_lines.append(f"Red Team Ozet: {network_summary.get('red_team_summary', '-')}")
        report_lines.append(f"MITRE ATT&CK: {network_summary.get('mitre_summary', '-')}")
    else:
        report_lines.append(f"Blue Team Ozet: {network_summary.get('blue_team_summary', '-')}")
        if network_summary.get("priority_action_plan"):
            report_lines.append("ONCELIKLENDIRILMIS AKSIYON PLANI")
            for item in network_summary["priority_action_plan"]:
                report_lines.append(
                    f"{item['order']}. {item['title']} | {item['detail']} | Oncelik Puani: {item['score']}"
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
        report_lines.append(f"Firewall Tespiti: {'Evet, filtered portlar bulundu.' if host['firewall_detected'] else 'Belirgin firewall gostergesi yok.'}")
        report_lines.append(f"Brute-Force Riskli Servis Sayisi: {host['brute_force_risk_count']}")
        report_lines.append(f"Saldiri Senaryosu Sayisi: {len(host.get('attack_scenarios', []))}")
        report_lines.append(f"Senaryo Etki Skoru: {host.get('scenario_impact_score', 0)}")
        report_lines.append(f"Genel Risk Seviyesi: {host['general_risk']}")
        report_lines.append(f"Risk Skoru: {host['host_score']}")
        report_lines.append("")

        if mode == "red":
            report_lines.append(f"Red Team Ozeti: {host.get('red_team_summary', '-')}")
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
                        report_lines.append("MITRE ATT&CK ESMELEMELERI")
                        for item in scenario["mitre_attack"]:
                            report_lines.append(
                                f"- {item['tactic']} | {item['technique_id']} | {item['technique']}"
                            )
                    report_lines.append("")
        else:
            report_lines.append(f"Blue Team Onceligi: {host.get('blue_team_priority', 'Normal')}")
            if host.get("priority_actions"):
                report_lines.append("HOST ICIN SIRALI AKSIYONLAR")
                for index, item in enumerate(host["priority_actions"][:4], start=1):
                    report_lines.append(
                        f"{index}. {item['title']} | {item['detail']} | Oncelik Puani: {item['score']}"
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


def generate_pdf_report(network_summary, host_reports, comparison=None, mode="red"):
    if not REPORTLAB_AVAILABLE:
        return False

    os.makedirs(REPORTS_DIR, exist_ok=True)
    report_lines = build_text_report_lines(network_summary, host_reports, comparison, mode=mode)

    pdf = canvas.Canvas(PDF_RAPOR_DOSYASI, pagesize=A4)
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


def generate_html_report(network_summary, host_reports, comparison=None, mode="red"):
    os.makedirs(REPORTS_DIR, exist_ok=True)
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
    <h1>Ag Tarama Sonuclari Icin Akilli Raporlama Sistemi</h1>

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
        <p><strong>Brute-Force Riski Olan Host Sayisi:</strong> {network_summary['brute_force_risk_hosts']}</p>
        <p><strong>Saldiri Senaryosu Uretilen Host Sayisi:</strong> {network_summary['scenario_host_count']}</p>
        <p><strong>Toplam Saldiri Senaryosu:</strong> {network_summary['scenario_count']}</p>
        <p><strong>Toplam Senaryo Etki Skoru:</strong> {network_summary['scenario_total_impact_score']}</p>
        <p><strong>MITRE ATT&CK Teknik Sayisi:</strong> {network_summary.get('mitre_technique_count', 0)}</p>
        <p><strong>CVE Veri Kaynagi:</strong> {network_summary.get('cve_data_source', 'Yerel esleme')}</p>
        <p><strong>En Riskli Host:</strong> {network_summary['most_risky_host']}</p>
    </div>

    <div class="card mode-card">
        <h2>{mode_label(mode)} Modu</h2>
        <p><strong>Soru:</strong> {mode_question(mode)}</p>
        <p>{network_summary.get('red_team_summary' if mode == 'red' else 'blue_team_summary', '-')}</p>
        <p><strong>MITRE ATT&CK:</strong> {network_summary.get('mitre_summary', '-')}</p>
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
                <td>{host['ip']}</td>
                <td>{host['detected_os']}</td>
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

    if mode == "blue" and network_summary.get("priority_action_plan"):
        html += """
        <div class="card">
            <h2>Onceliklendirilmis Aksiyon Plani</h2>
            <ol>
        """
        for item in network_summary["priority_action_plan"]:
            html += (
                f"<li><strong>{item['title']}</strong><br>"
                f"<small>{item['detail']} | Oncelik Puani: {item['score']}</small></li>"
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
            <h2>Host: {host['ip']}</h2>
            <p><strong>Tespit Edilen Isletim Sistemi:</strong> {host['detected_os']}</p>
            <p><strong>Toplam Acik Port Sayisi:</strong> {host['total_open_ports']}</p>
            <p><strong>Filtered Port Sayisi:</strong> {host['total_filtered_ports']}</p>
            <p><strong>Firewall Tespiti:</strong> {"Evet, filtered portlar bulundu." if host['firewall_detected'] else "Belirgin firewall gostergesi yok."}</p>
            <p><strong>Brute-Force Riskli Servis Sayisi:</strong> {host['brute_force_risk_count']}</p>
            <p><strong>Saldiri Senaryosu Sayisi:</strong> {len(host.get('attack_scenarios', []))}</p>
            <p><strong>Senaryo Etki Skoru:</strong> {host.get('scenario_impact_score', 0)}</p>
            <p><strong>Genel Risk Seviyesi:</strong> <span class="{risk_class(host['general_risk'])}">{host['general_risk']}</span></p>
            <p><strong>Risk Skoru:</strong> {host['host_score']}</p>
        """

        if mode == "red":
            html += f"<p><strong>Red Team Ozeti:</strong> {host.get('red_team_summary', '-')}</p>"
            if host.get("attack_scenarios"):
                html += "<h3>Saldiri Senaryosu Simulasyonu</h3>"
                for scenario in host["attack_scenarios"]:
                    html += f"""
                    <div style="margin-bottom: 16px; padding: 14px; border: 1px solid #ddd; border-radius: 8px;">
                        <p><strong>Senaryo:</strong> {scenario['title']}</p>
                        <p><strong>Siddet:</strong> {scenario['severity']} | <strong>Etki Skoru:</strong> {scenario['impact_score']}/10</p>
                        <ol>
                    """
                    for step in scenario["steps"]:
                        html += f"<li>{step}</li>"
                    html += f"""
                        </ol>
                        <p><strong>Sonuc:</strong> {scenario['result']}</p>
                        <p><strong>Etki:</strong> {scenario['impact']}</p>
                    """
                    if scenario.get("mitre_attack"):
                        html += "<p><strong>MITRE ATT&CK Eslesmeleri:</strong></p><ul class=\"action-list\">"
                        for item in scenario["mitre_attack"]:
                            html += f"<li>{item['tactic']} - {item['technique_id']} - {item['technique']}</li>"
                        html += "</ul>"
                    html += "</div>"
        else:
            html += f"<p><strong>Blue Team Onceligi:</strong> {host.get('blue_team_priority', 'Normal')}</p>"
            if host.get("priority_actions"):
                html += "<h3>Host Icin Sirali Aksiyonlar</h3><ol>"
                for item in host.get("priority_actions", [])[:4]:
                    html += (
                        f"<li><strong>{item['title']}</strong><br>"
                        f"<small>{item['detail']} | Oncelik Puani: {item['score']}</small></li>"
                    )
                html += "</ol>"
            html += "<h3>Savunma Onerileri</h3><ul class=\"action-list\">"
            for action in host.get("blue_team_actions", []):
                html += f"<li>{action}</li>"
            html += "</ul>"

        html += """
            <h3>Acik Portlar ve Analiz</h3>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Protokol</th>
                    <th>Servis</th>
                    <th>Surum Tespiti</th>
                    <th>Kategori</th>
                    <th>Risk</th>
                    <th>OS Etkisi</th>
                    <th>Brute-Force Riski</th>
                    <th>Bilinen CVE</th>
                    <th>Oneri</th>
                </tr>
        """

        for port in host["open_ports_data"]:
            cve_html = "Bilinen eslesme yok"
            if port["cves"]:
                cve_html = "<ul class=\"cve-list\">"
                for cve in port["cves"]:
                    cve_html += (
                        f"<li><strong>{cve['cve_id']}</strong> - {cve['title']}<br>"
                        f"<small>Kaynak: {cve.get('source', 'Yerel esleme')} | "
                        f"Siddet: {cve.get('severity', 'Bilinmiyor')}</small><br>"
                        f"<small>Eslesme Nedeni: {cve.get('match_reason', 'Kural eslesmesi bulundu.')}</small><br>"
                        f"<small>{cve['description']}</small></li>"
                    )
                cve_html += "</ul>"

            html += f"""
                <tr>
                    <td>{port['port']}</td>
                    <td>{port['protocol']}</td>
                    <td>{port['service']}</td>
                    <td>{port['service_version']}</td>
                    <td>{port['category']}</td>
                    <td class="{risk_class(port['risk'])}">{port['risk']}</td>
                    <td>{port['os_risk_note']}</td>
                    <td>{port['brute_force_note']}</td>
                    <td>{cve_html}</td>
                    <td>{port['recommendation']}</td>
                </tr>
            """

        html += """
            </table>
        </div>
        """

    html += """
</body>
</html>
    """

    with open(HTML_RAPOR_DOSYASI, "w", encoding="utf-8") as file:
        file.write(html)


def generate_text_report(network_summary, host_reports, comparison=None, mode="red"):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    report_lines = build_text_report_lines(network_summary, host_reports, comparison, mode=mode)

    with open(TXT_RAPOR_DOSYASI, "w", encoding="utf-8") as file:
        for line in report_lines:
            file.write(line + "\n")


def generate_reports(network_summary, host_reports, comparison=None, mode="red"):
    generate_html_report(network_summary, host_reports, comparison, mode=mode)
    generate_text_report(network_summary, host_reports, comparison, mode=mode)
    generate_pdf_report(network_summary, host_reports, comparison, mode=mode)
