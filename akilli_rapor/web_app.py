import os

from flask import Flask, Response, render_template, request, send_file

from analyzer import parse_results
from chart_generator import generate_network_topology, generate_os_chart, generate_risk_chart
from cve_lookup import enrich_reports_with_online_cves
from env_loader import load_env_file
from history_tracker import record_and_compare_scan
from reporter import (
    HTML_RAPOR_DOSYASI,
    PDF_RAPOR_DOSYASI,
    TXT_RAPOR_DOSYASI,
    build_printable_report_html,
    can_generate_pdf,
    generate_reports,
)
from scenario_generator import generate_attack_scenarios
from scanner import run_nmap_scan
from team_advisor import BLUE_TEAM, RED_TEAM, apply_team_mode_analysis


load_env_file()

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    network_summary = None
    host_reports = None
    comparison = None
    error = None
    target = ""
    team_mode = RED_TEAM

    if request.method == "POST":
        target = request.form.get("target", "").strip()
        team_mode = request.form.get("team_mode", RED_TEAM).strip().lower()
        if team_mode not in {RED_TEAM, BLUE_TEAM}:
            team_mode = RED_TEAM

        if not target:
            error = "Lütfen hedef IP veya ağ aralığı girin."
        else:
            success, stderr = run_nmap_scan(target)
            if success:
                try:
                    network_summary, host_reports = parse_results()
                    enrich_reports_with_online_cves(network_summary, host_reports)
                    generate_attack_scenarios(network_summary, host_reports)
                    apply_team_mode_analysis(network_summary, host_reports)
                    comparison = record_and_compare_scan(target, network_summary, host_reports)
                    generate_risk_chart(network_summary)
                    generate_os_chart(network_summary)
                    generate_network_topology(target, network_summary)
                    generate_reports(network_summary, host_reports, comparison, mode=team_mode)
                except ValueError as parse_error:
                    error = str(parse_error)
            else:
                error = f"Nmap hatası: {stderr}"

    return render_template(
        "index.html",
        network_summary=network_summary,
        host_reports=host_reports,
        comparison=comparison,
        error=error,
        target=target,
        team_mode=team_mode,
    )


@app.route("/report")
def download_report():
    return send_file(HTML_RAPOR_DOSYASI)


@app.route("/report/txt")
def download_text_report():
    return send_file(TXT_RAPOR_DOSYASI, mimetype="text/plain; charset=utf-8")


@app.route("/report/pdf")
def printable_report():
    if can_generate_pdf() and os.path.exists(PDF_RAPOR_DOSYASI):
        return send_file(
            PDF_RAPOR_DOSYASI,
            mimetype="application/pdf",
            as_attachment=True,
            download_name="report.pdf",
        )

    html = build_printable_report_html()
    if html is None:
        return Response("PDF için önce bir rapor oluşturun.", status=404, mimetype="text/plain; charset=utf-8")
    return Response(html, mimetype="text/html; charset=utf-8")


if __name__ == "__main__":
    os.makedirs(os.path.join(app.root_path, "static"), exist_ok=True)
    # Tarama sonrasi uretilen rapor/gorsel dosyalari Flask reloader'ini tetikleyip
    # gelistirme sunucusunun yeniden baslamasina neden olabiliyor.
    app.run(debug=True, use_reloader=False)
