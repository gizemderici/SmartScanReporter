(function () {
    const dataNode = document.getElementById("dashboard-chart-data");
    if (!dataNode) {
        return;
    }

    let payload;
    try {
        payload = JSON.parse(dataNode.textContent);
    } catch (error) {
        return;
    }

    function getThemeTokens() {
        const styles = window.getComputedStyle(document.body);
        return {
            text: styles.getPropertyValue("--text").trim() || "#d8e5f5",
            heading: styles.getPropertyValue("--heading").trim() || "#f7fbff",
            line: styles.getPropertyValue("--line").trim() || "rgba(255,255,255,0.12)",
        };
    }

    function normalizeOsDistribution(osValues) {
        const totals = {
            Linux: 0,
            Windows: 0,
            Unknown: 0,
        };

        (osValues || []).forEach(function (value) {
            const normalized = String(value || "").toLowerCase();
            if (normalized.includes("linux") || normalized.includes("ubuntu") || normalized.includes("debian")) {
                totals.Linux += 1;
            } else if (normalized.includes("windows")) {
                totals.Windows += 1;
            } else {
                totals.Unknown += 1;
            }
        });

        const totalHosts = totals.Linux + totals.Windows + totals.Unknown || 1;
        return [
            { label: "Linux", value: Math.round((totals.Linux / totalHosts) * 100), color: "#31d39b" },
            { label: "Windows", value: Math.round((totals.Windows / totalHosts) * 100), color: "#35d0ff" },
            { label: "Unknown", value: Math.round((totals.Unknown / totalHosts) * 100), color: "#94a3b8" },
        ];
    }

    function buildCanvasShell(target) {
        target.innerHTML = "";
        const wrap = document.createElement("div");
        wrap.className = "chart-canvas-wrap";

        const canvas = document.createElement("canvas");
        canvas.className = "chart-canvas";
        canvas.width = 760;
        canvas.height = 220;

        const legend = document.createElement("div");
        legend.className = "chart-legend";

        wrap.appendChild(canvas);
        target.appendChild(wrap);
        target.appendChild(legend);

        return { canvas: canvas, legend: legend };
    }

    function renderLegend(legendNode, rows, formatter) {
        legendNode.innerHTML = rows.map(function (item) {
            return (
                '<div class="chart-row">' +
                    '<div class="chart-label">' + item.label + '</div>' +
                    '<div class="chart-track"><div class="chart-fill" style="width:' + Math.max(6, item.percent) + '%; background:' + item.color + ';"></div></div>' +
                    '<div class="chart-value">' + formatter(item) + '</div>' +
                '</div>'
            );
        }).join("");
    }

    function animateBars(canvas, rows, maxValue) {
        const context = canvas.getContext("2d");
        if (!context) {
            return;
        }
        const theme = getThemeTokens();

        const width = canvas.width;
        const height = canvas.height;
        const leftPad = 24;
        const topPad = 24;
        const rowHeight = 28;
        const gap = 16;
        const barHeight = 14;
        const chartWidth = width - leftPad - 36;
        const totalHeight = rows.length * (rowHeight + gap);
        const offsetY = Math.max(topPad, (height - totalHeight) / 2);
        const start = performance.now();
        const duration = 800;

        function frame(now) {
            const progress = Math.min(1, (now - start) / duration);
            const eased = 1 - Math.pow(1 - progress, 3);

            context.clearRect(0, 0, width, height);

            rows.forEach(function (item, index) {
                const y = offsetY + index * (rowHeight + gap);
                const baseY = y + 18;
                const percent = maxValue > 0 ? item.value / maxValue : 0;
                const animatedWidth = Math.max(8, chartWidth * percent * eased);

                context.fillStyle = theme.line;
                roundRect(context, leftPad, baseY, chartWidth, barHeight, 999);
                context.fill();

                context.fillStyle = item.color;
                roundRect(context, leftPad, baseY, animatedWidth, barHeight, 999);
                context.fill();

                context.fillStyle = theme.text;
                context.font = "600 12px Segoe UI";
                context.fillText(item.label, leftPad, y);

                context.fillStyle = theme.heading;
                context.font = "700 12px Segoe UI";
                context.textAlign = "right";
                context.fillText(item.displayValue, width - 12, y + 11);
                context.textAlign = "left";
            });

            if (progress < 1) {
                window.requestAnimationFrame(frame);
            }
        }

        window.requestAnimationFrame(frame);
    }

    function roundRect(context, x, y, width, height, radius) {
        const safeRadius = Math.min(radius, height / 2, width / 2);
        context.beginPath();
        context.moveTo(x + safeRadius, y);
        context.arcTo(x + width, y, x + width, y + height, safeRadius);
        context.arcTo(x + width, y + height, x, y + height, safeRadius);
        context.arcTo(x, y + height, x, y, safeRadius);
        context.arcTo(x, y, x + width, y, safeRadius);
        context.closePath();
    }

    function renderCanvasChart(targetId, rows, formatter) {
        const target = document.getElementById(targetId);
        if (!target || !Array.isArray(rows) || rows.length === 0) {
            return;
        }

        const maxValue = Math.max.apply(
            null,
            rows.map(function (item) {
                return Number(item.value || 0);
            }).concat([1])
        );

        const preparedRows = rows.map(function (item) {
            return {
                label: item.label,
                value: Number(item.value || 0),
                color: item.color || "#35d0ff",
                displayValue: formatter(item),
                percent: Math.round((Number(item.value || 0) / maxValue) * 100),
            };
        });

        const shell = buildCanvasShell(target);
        renderLegend(shell.legend, preparedRows, function (item) {
            return item.displayValue;
        });
        animateBars(shell.canvas, preparedRows, maxValue);
    }

    function buildOpenPortRows() {
        return (payload.openPortBreakdown || []).slice(0, 6).map(function (item, index) {
            const colors = ["#35d0ff", "#31d39b", "#ffb54a", "#ff6177", "#7c9cff", "#00c2a8"];
            return {
                label: item.label,
                value: Number(item.value || 0),
                color: colors[index % colors.length],
            };
        });
    }

    function renderAllCharts() {
        const openPortRows = buildOpenPortRows();
        if (payload.totalOpenPorts && openPortRows.length > 0) {
            openPortRows.unshift({
                label: "Toplam",
                value: Number(payload.totalOpenPorts || 0),
                color: "#73ecff",
            });
        }

        renderCanvasChart("open-port-chart", openPortRows, function (item) {
            return String(item.value);
        });
        renderCanvasChart("risk-level-chart", payload.riskLevels || [], function (item) {
            return String(item.value);
        });
        renderCanvasChart("os-distribution-chart", normalizeOsDistribution(payload.osDistribution || []), function (item) {
            return String(item.value) + "%";
        });
    }

    window.addEventListener("dashboard-theme-change", function () {
        window.requestAnimationFrame(renderAllCharts);
    });

    window.addEventListener("resize", function () {
        window.requestAnimationFrame(renderAllCharts);
    });

    renderAllCharts();
})();
