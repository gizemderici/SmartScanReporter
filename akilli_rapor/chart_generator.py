import os

import matplotlib.pyplot as plt

try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False


BASE_DIR = os.path.dirname(__file__)
STATIC_DIR = os.path.join(BASE_DIR, "static")
RISK_CHART_PATH = os.path.join(STATIC_DIR, "risk_chart.png")
TOPOLOGY_CHART_PATH = os.path.join(STATIC_DIR, "network_topology.png")
OS_CHART_PATH = os.path.join(STATIC_DIR, "os_distribution.png")

RISK_COLORS = {
    "Yüksek": "#d9534f",
    "Orta": "#f0ad4e",
    "Düşük": "#5cb85c",
    "Bilinmiyor": "#94a3b8",
}


def generate_risk_chart(network_summary):
    labels = ["Yüksek", "Orta", "Düşük"]
    values = [
        network_summary["high_risk_hosts"],
        network_summary["medium_risk_hosts"],
        network_summary["low_risk_hosts"],
    ]

    os.makedirs(STATIC_DIR, exist_ok=True)

    plt.figure(figsize=(6, 4))
    plt.bar(labels, values, color=["#d9534f", "#f0ad4e", "#5cb85c"])
    plt.title("Host Risk Dağılımı")
    plt.xlabel("Risk Seviyesi")
    plt.ylabel("Host Sayısı")
    plt.tight_layout()
    plt.savefig(RISK_CHART_PATH)
    plt.close()


def generate_os_chart(network_summary):
    os.makedirs(STATIC_DIR, exist_ok=True)

    labels = {}
    for host in network_summary.get("host_list", []):
        os_name = host.get("detected_os", "Bilinmiyor")
        labels[os_name] = labels.get(os_name, 0) + 1

    if not labels:
        labels = {"Bilinmiyor": 1}

    names = list(labels.keys())
    values = list(labels.values())

    plt.figure(figsize=(7, 4.5))
    plt.barh(names, values, color="#3b82f6")
    plt.title("İşletim Sistemi Dağılımı")
    plt.xlabel("Host Sayısı")
    plt.ylabel("OS")
    plt.tight_layout()
    plt.savefig(OS_CHART_PATH)
    plt.close()


def generate_network_topology(target, network_summary):
    os.makedirs(STATIC_DIR, exist_ok=True)

    host_list = network_summary.get("host_list", [])
    host_ips = [host["ip"] for host in host_list]
    host_colors = [
        RISK_COLORS.get(host.get("general_risk", "Bilinmiyor"), RISK_COLORS["Bilinmiyor"])
        for host in host_list
    ]
    if not host_ips:
        plt.figure(figsize=(8, 5))
        plt.text(0.5, 0.5, "Topoloji için aktif host bulunamadı", ha="center", va="center", fontsize=14)
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(TOPOLOGY_CHART_PATH)
        plt.close()
        return

    if NETWORKX_AVAILABLE:
        graph = nx.Graph()
        scanner_node = "Tarayan Sistem"
        router_node = f"Hedef Ağ\n{target}"

        graph.add_edge(scanner_node, router_node)
        for ip in host_ips:
            graph.add_edge(router_node, ip)

        positions = {
            scanner_node: (-1.6, 0.0),
            router_node: (0.0, 0.0),
        }

        total = max(len(host_ips), 1)
        for index, ip in enumerate(host_ips):
            offset = index - (total - 1) / 2
            positions[ip] = (1.6, offset * 0.8)

        plt.figure(figsize=(10, 6))
        nx.draw_networkx_edges(graph, positions, width=2.0, edge_color="#94a3b8")
        nx.draw_networkx_nodes(graph, positions, nodelist=[scanner_node], node_color="#2563eb", node_size=2200)
        nx.draw_networkx_nodes(graph, positions, nodelist=[router_node], node_color="#f59e0b", node_size=2600)
        nx.draw_networkx_nodes(graph, positions, nodelist=host_ips, node_color=host_colors, node_size=1800)
        nx.draw_networkx_labels(graph, positions, font_size=9, font_weight="bold", font_color="#111827")
        _add_risk_legend()
        plt.title("Network Topology", fontsize=16)
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(TOPOLOGY_CHART_PATH)
        plt.close()
        return

    plt.figure(figsize=(10, 6))
    plt.scatter([-1.6], [0], s=2200, c="#2563eb")
    plt.scatter([0], [0], s=2600, c="#f59e0b")

    total = max(len(host_ips), 1)
    y_positions = []
    for index in range(len(host_ips)):
        offset = index - (total - 1) / 2
        y_positions.append(offset * 0.8)

    plt.scatter([1.6] * len(host_ips), y_positions, s=1800, c=host_colors)
    plt.plot([-1.6, 0], [0, 0], color="#94a3b8", linewidth=2)

    for y in y_positions:
        plt.plot([0, 1.6], [0, y], color="#94a3b8", linewidth=2)

    plt.text(-1.6, 0, "Tarayan Sistem", ha="center", va="center", color="white", weight="bold")
    plt.text(0, 0, f"Hedef Ağ\n{target}", ha="center", va="center", color="#111827", weight="bold")

    for ip, y in zip(host_ips, y_positions):
        plt.text(1.6, y, ip, ha="center", va="center", color="#111827", weight="bold")

    _add_risk_legend()
    plt.title("Network Topology", fontsize=16)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(TOPOLOGY_CHART_PATH)
    plt.close()


def _add_risk_legend():
    handles = [
        plt.Line2D([0], [0], marker="o", color="w", label="Yüksek Risk", markerfacecolor=RISK_COLORS["Yüksek"], markersize=10),
        plt.Line2D([0], [0], marker="o", color="w", label="Orta Risk", markerfacecolor=RISK_COLORS["Orta"], markersize=10),
        plt.Line2D([0], [0], marker="o", color="w", label="Düşük Risk", markerfacecolor=RISK_COLORS["Düşük"], markersize=10),
        plt.Line2D([0], [0], marker="o", color="w", label="Bilinmiyor", markerfacecolor=RISK_COLORS["Bilinmiyor"], markersize=10),
    ]
    plt.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.02), ncol=4, frameon=False)
