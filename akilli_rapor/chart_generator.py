import os
import warnings

os.environ["MPLBACKEND"] = "Agg"

import matplotlib

matplotlib.use("Agg", force=True)
matplotlib.rcParams["figure.max_open_warning"] = 0
warnings.filterwarnings("ignore", message=".*Matplotlib.*")
warnings.filterwarnings("ignore", message=".*GUI.*")
import matplotlib.pyplot as plt

plt.ioff()

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
DISCOVERY_TOPOLOGY_CHART_PATH = os.path.join(STATIC_DIR, "discovery_topology.png")

RISK_COLORS = {
    "Yuksek": "#d9534f",
    "Orta": "#f0ad4e",
    "Dusuk": "#5cb85c",
    "Bilinmiyor": "#94a3b8",
}


def generate_risk_chart(network_summary, output_path=RISK_CHART_PATH):
    labels = ["Yuksek", "Orta", "Dusuk"]
    values = [
        network_summary["high_risk_hosts"],
        network_summary["medium_risk_hosts"],
        network_summary["low_risk_hosts"],
    ]

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    plt.figure(figsize=(8, 5), dpi=100)
    bars = plt.bar(labels, values, color=["#d9534f", "#f0ad4e", "#5cb85c"], edgecolor="black", linewidth=1.5)
    plt.title("Host Risk Dagilimi", fontsize=14, fontweight="bold")
    plt.xlabel("Risk Seviyesi", fontsize=12)
    plt.ylabel("Host Sayisi", fontsize=12)
    plt.grid(axis="y", alpha=0.3, linestyle="--")
    for bar in bars:
        height = bar.get_height()
        if height > 0:
            plt.text(bar.get_x() + bar.get_width() / 2.0, height, f"{int(height)}", ha="center", va="bottom", fontweight="bold")
    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches="tight")
    plt.close()


def generate_os_chart(network_summary, output_path=OS_CHART_PATH):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    labels = {}
    for host in network_summary.get("host_list", []):
        os_name = host.get("detected_os", "Bilinmiyor")
        labels[os_name] = labels.get(os_name, 0) + 1

    if not labels:
        labels = {"Bilinmiyor": 1}

    names = list(labels.keys())
    values = list(labels.values())

    plt.figure(figsize=(10, 6), dpi=100)
    bars = plt.barh(names, values, color="#3b82f6", edgecolor="black", linewidth=1.5)
    plt.title("Isletim Sistemi Dagilimi", fontsize=14, fontweight="bold")
    plt.xlabel("Host Sayisi", fontsize=12)
    plt.ylabel("OS", fontsize=12)
    plt.grid(axis="x", alpha=0.3, linestyle="--")
    for bar in bars:
        width = bar.get_width()
        if width > 0:
            plt.text(width, bar.get_y() + bar.get_height() / 2.0, f" {int(width)}", ha="left", va="center", fontweight="bold")
    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches="tight")
    plt.close()


def generate_network_topology(target, network_summary, output_path=TOPOLOGY_CHART_PATH):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    host_list = network_summary.get("host_list", [])
    host_ips = [host["ip"] for host in host_list]
    host_colors = [
        RISK_COLORS.get(host.get("general_risk", "Bilinmiyor"), RISK_COLORS["Bilinmiyor"])
        for host in host_list
    ]
    if not host_ips:
        plt.figure(figsize=(10, 6), dpi=100)
        plt.text(0.5, 0.5, "Topoloji icin aktif host bulunamadi", ha="center", va="center", fontsize=14)
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(output_path, dpi=100, bbox_inches="tight")
        plt.close()
        return

    if NETWORKX_AVAILABLE:
        graph = nx.Graph()
        scanner_node = "Tarayan Sistem"
        router_node = f"Hedef Ag\n{target}"

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

        plt.figure(figsize=(12, 7), dpi=100)
        nx.draw_networkx_edges(graph, positions, width=2.0, edge_color="#94a3b8")
        nx.draw_networkx_nodes(graph, positions, nodelist=[scanner_node], node_color="#2563eb", node_size=2200)
        nx.draw_networkx_nodes(graph, positions, nodelist=[router_node], node_color="#f59e0b", node_size=2600)
        nx.draw_networkx_nodes(graph, positions, nodelist=host_ips, node_color=host_colors, node_size=1800)
        nx.draw_networkx_labels(graph, positions, font_size=9, font_weight="bold", font_color="#111827")
        _add_risk_legend()
        plt.title("Network Topology", fontsize=16, fontweight="bold")
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(output_path, dpi=100, bbox_inches="tight")
        plt.close()
        return

    plt.figure(figsize=(12, 7), dpi=100)
    plt.scatter([-1.6], [0], s=2200, c="#2563eb", edgecolors="black", linewidth=2)
    plt.scatter([0], [0], s=2600, c="#f59e0b", edgecolors="black", linewidth=2)

    total = max(len(host_ips), 1)
    y_positions = []
    for index in range(len(host_ips)):
        offset = index - (total - 1) / 2
        y_positions.append(offset * 0.8)

    plt.scatter([1.6] * len(host_ips), y_positions, s=1800, c=host_colors, edgecolors="black", linewidth=2)
    plt.plot([-1.6, 0], [0, 0], color="#94a3b8", linewidth=2)

    for y in y_positions:
        plt.plot([0, 1.6], [0, y], color="#94a3b8", linewidth=2)

    plt.text(-1.6, 0, "Tarayan Sistem", ha="center", va="center", color="white", weight="bold", fontsize=10)
    plt.text(0, 0, f"Hedef Ag\n{target}", ha="center", va="center", color="#111827", weight="bold", fontsize=10)

    for ip, y in zip(host_ips, y_positions):
        plt.text(1.6, y, ip, ha="center", va="center", color="#111827", weight="bold", fontsize=9)

    _add_risk_legend()
    plt.title("Network Topology", fontsize=16, fontweight="bold")
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches="tight")
    plt.close()


def generate_discovery_topology(target, devices, output_path=DISCOVERY_TOPOLOGY_CHART_PATH):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    device_ips = [device.get("ip", "Bilinmiyor") for device in devices]
    if not device_ips:
        plt.figure(figsize=(10, 6), dpi=100)
        plt.text(0.5, 0.5, "Discovery topolojisi icin aktif cihaz bulunamadi", ha="center", va="center", fontsize=14)
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(output_path, dpi=100, bbox_inches="tight")
        plt.close()
        return

    if NETWORKX_AVAILABLE:
        graph = nx.Graph()
        scanner_node = "Tarayan Sistem"
        subnet_node = f"Subnet\n{target}"

        graph.add_edge(scanner_node, subnet_node)
        for ip in device_ips:
            graph.add_edge(subnet_node, ip)

        positions = {
            scanner_node: (-1.6, 0.0),
            subnet_node: (0.0, 0.0),
        }

        total = max(len(device_ips), 1)
        for index, ip in enumerate(device_ips):
            offset = index - (total - 1) / 2
            positions[ip] = (1.7, offset * 0.8)

        plt.figure(figsize=(12, 7), dpi=100)
        nx.draw_networkx_edges(graph, positions, width=2.0, edge_color="#94a3b8")
        nx.draw_networkx_nodes(graph, positions, nodelist=[scanner_node], node_color="#2563eb", node_size=2200)
        nx.draw_networkx_nodes(graph, positions, nodelist=[subnet_node], node_color="#f59e0b", node_size=2600)
        nx.draw_networkx_nodes(graph, positions, nodelist=device_ips, node_color="#31d39b", node_size=1700)
        nx.draw_networkx_labels(graph, positions, font_size=9, font_weight="bold", font_color="#111827")
        plt.title("Network Discovery Topology", fontsize=16, fontweight="bold")
        plt.axis("off")
        plt.tight_layout()
        plt.savefig(output_path, dpi=100, bbox_inches="tight")
        plt.close()
        return

    plt.figure(figsize=(12, 7), dpi=100)
    plt.scatter([-1.6], [0], s=2200, c="#2563eb", edgecolors="black", linewidth=2)
    plt.scatter([0], [0], s=2600, c="#f59e0b", edgecolors="black", linewidth=2)

    total = max(len(device_ips), 1)
    y_positions = []
    for index in range(len(device_ips)):
        offset = index - (total - 1) / 2
        y_positions.append(offset * 0.8)

    plt.scatter([1.7] * len(device_ips), y_positions, s=1700, c="#31d39b", edgecolors="black", linewidth=2)
    plt.plot([-1.6, 0], [0, 0], color="#94a3b8", linewidth=2)

    for y in y_positions:
        plt.plot([0, 1.7], [0, y], color="#94a3b8", linewidth=2)

    plt.text(-1.6, 0, "Tarayan Sistem", ha="center", va="center", color="white", weight="bold", fontsize=10)
    plt.text(0, 0, f"Subnet\n{target}", ha="center", va="center", color="#111827", weight="bold", fontsize=10)

    for ip, y in zip(device_ips, y_positions):
        plt.text(1.7, y, ip, ha="center", va="center", color="#111827", weight="bold", fontsize=9)

    plt.title("Network Discovery Topology", fontsize=16, fontweight="bold")
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, dpi=100, bbox_inches="tight")
    plt.close()


def _add_risk_legend():
    handles = [
        plt.Line2D([0], [0], marker="o", color="w", label="Yuksek Risk", markerfacecolor=RISK_COLORS["Yuksek"], markersize=10),
        plt.Line2D([0], [0], marker="o", color="w", label="Orta Risk", markerfacecolor=RISK_COLORS["Orta"], markersize=10),
        plt.Line2D([0], [0], marker="o", color="w", label="Dusuk Risk", markerfacecolor=RISK_COLORS["Dusuk"], markersize=10),
        plt.Line2D([0], [0], marker="o", color="w", label="Bilinmiyor", markerfacecolor=RISK_COLORS["Bilinmiyor"], markersize=10),
    ]
    plt.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.02), ncol=4, frameon=False)
