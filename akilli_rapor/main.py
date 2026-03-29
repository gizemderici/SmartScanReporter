from analyzer import parse_results
from chart_generator import generate_risk_chart
from cve_lookup import enrich_reports_with_online_cves
from env_loader import load_env_file
from history_tracker import record_and_compare_scan
from reporter import HTML_RAPOR_DOSYASI, TXT_RAPOR_DOSYASI, generate_reports
from scenario_generator import generate_attack_scenarios
from scanner import run_nmap_scan
from team_advisor import BLUE_TEAM, RED_TEAM, apply_team_mode_analysis


load_env_file()


def main():
    target = input("Lutfen hedef IP veya ag araligi girin: ").strip()
    selected_mode = input("Mod secin (red/blue, varsayilan red): ").strip().lower() or RED_TEAM
    if selected_mode not in {RED_TEAM, BLUE_TEAM}:
        selected_mode = RED_TEAM

    if not target:
        print("Hedef bos birakilamaz.")
        return

    success, stderr = run_nmap_scan(target)
    if not success:
        print(f"Nmap hatasi: {stderr}")
        return

    try:
        network_summary, host_reports = parse_results()
        enrich_reports_with_online_cves(network_summary, host_reports)
        generate_attack_scenarios(network_summary, host_reports)
        apply_team_mode_analysis(network_summary, host_reports)
        comparison = record_and_compare_scan(target, network_summary, host_reports)
        generate_risk_chart(network_summary)
        generate_reports(network_summary, host_reports, comparison, mode=selected_mode)
    except ValueError as parse_error:
        print(f"Analiz hatasi: {parse_error}")
        return

    if comparison["has_previous"]:
        print(f"\nOnceki tarama zamani: {comparison['previous_scan_time']}")
        print(f"Yeni acilan port sayisi: {comparison['summary']['new_port_count']}")
        print(f"Kapanan port sayisi: {comparison['summary']['closed_port_count']}")
        print(f"Risk artisi gorulen host sayisi: {comparison['summary']['risk_increase_count']}")
    else:
        print("\nIlk snapshot kaydedildi. Zaman karsilastirmasi bir sonraki taramada olusacak.")

    print(f"\nTXT rapor olusturuldu: {TXT_RAPOR_DOSYASI}")
    print(f"HTML rapor olusturuldu: {HTML_RAPOR_DOSYASI}")
    print(f"Aktif analiz modu: {'Red Team' if selected_mode == RED_TEAM else 'Blue Team'}")


if __name__ == "__main__":
    main()
