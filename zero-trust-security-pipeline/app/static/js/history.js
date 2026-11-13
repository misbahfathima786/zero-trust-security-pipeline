// ========================================================
// PAGE 7: SECURITY HISTORY & TRENDS INTERACTIVE CHART SCRIPT
// ========================================================

document.addEventListener("DOMContentLoaded", function () {
    const rangeSelect = document.getElementById("history-range-select");
    const container = document.getElementById("chart-container");
    const svg = document.getElementById("trend-svg");
    const tooltip = document.getElementById("chart-tooltip");

    if (rangeSelect) {
        rangeSelect.addEventListener("change", function () {
            const val = rangeSelect.value;
            window.location.href = `${window.location.pathname}?range=${val}`;
        });
    }

    if (!container || !svg) return;

    let historyData = null;
    try {
        const raw = container.getAttribute("data-history");
        historyData = JSON.parse(raw);
    } catch (e) {
        console.error("Failed to parse history data attribute:", e);
        return;
    }

    if (!historyData || !historyData.labels || historyData.labels.length === 0) {
        return;
    }

    renderChart(historyData);

    window.addEventListener("resize", function () {
        renderChart(historyData);
    });

    function renderChart(data) {
        svg.innerHTML = "";

        const labels = data.labels;
        const critical = data.critical_series;
        const high = data.high_series;
        const medium = data.medium_series;
        const low = data.low_series;

        const width = 760;
        const height = 300;
        const padding = { top: 25, right: 30, bottom: 45, left: 45 };

        const chartW = width - padding.left - padding.right;
        const chartH = height - padding.top - padding.bottom;

        // Compute max value for Y-axis
        const allValues = [...critical, ...high, ...medium, ...low];
        const maxVal = Math.max(...allValues, 5);
        // Round maxVal up to multiple of 5 or 10
        const yMax = Math.ceil(maxVal / 5) * 5;

        // Draw horizontal grid lines & Y labels
        const gridSteps = 4;
        for (let i = 0; i <= gridSteps; i++) {
            const yVal = Math.round((yMax / gridSteps) * i);
            const yPos = padding.top + chartH - (yVal / yMax) * chartH;

            // Line
            const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
            line.setAttribute("x1", padding.left);
            line.setAttribute("y1", yPos);
            line.setAttribute("x2", width - padding.right);
            line.setAttribute("y2", yPos);
            line.setAttribute("class", "chart-grid-line");
            svg.appendChild(line);

            // Text
            const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
            text.setAttribute("x", padding.left - 12);
            text.setAttribute("y", yPos + 4);
            text.setAttribute("text-anchor", "end");
            text.setAttribute("class", "chart-axis-text");
            text.textContent = yVal;
            svg.appendChild(text);
        }

        // Draw X-axis labels
        const stepX = labels.length > 1 ? chartW / (labels.length - 1) : chartW / 2;
        labels.forEach(function (lbl, idx) {
            const xPos = labels.length > 1 ? padding.left + idx * stepX : padding.left + chartW / 2;
            const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
            text.setAttribute("x", xPos);
            text.setAttribute("y", height - 12);
            text.setAttribute("text-anchor", "middle");
            text.setAttribute("class", "chart-axis-text");
            text.textContent = lbl;
            svg.appendChild(text);
        });

        // Series definition
        const series = [
            { name: "Critical", color: "#c72f40", data: critical, cls: "chart-line--critical" },
            { name: "High", color: "#c7640f", data: high, cls: "chart-line--high" },
            { name: "Medium", color: "#d49300", data: medium, cls: "chart-line--medium" },
            { name: "Low", color: "#1b6b49", data: low, cls: "chart-line--low" },
        ];

        // Draw lines
        series.forEach(function (s) {
            if (s.data.length === 0) return;

            let pathD = "";
            s.data.forEach(function (val, idx) {
                const xPos = labels.length > 1 ? padding.left + idx * stepX : padding.left + chartW / 2;
                const yPos = padding.top + chartH - (val / yMax) * chartH;

                if (idx === 0) {
                    pathD += `M ${xPos} ${yPos}`;
                } else {
                    pathD += ` L ${xPos} ${yPos}`;
                }
            });

            const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
            path.setAttribute("d", pathD);
            path.setAttribute("class", `chart-line ${s.cls}`);
            svg.appendChild(path);
        });

        // Draw interactive points on top
        labels.forEach(function (lbl, idx) {
            const xPos = labels.length > 1 ? padding.left + idx * stepX : padding.left + chartW / 2;

            series.forEach(function (s) {
                const val = s.data[idx];
                const yPos = padding.top + chartH - (val / yMax) * chartH;

                const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
                circle.setAttribute("cx", xPos);
                circle.setAttribute("cy", yPos);
                circle.setAttribute("r", "4.5");
                circle.setAttribute("fill", "#ffffff");
                circle.setAttribute("stroke", s.color);
                circle.setAttribute("stroke-width", "2.5");
                circle.setAttribute("class", "chart-point");

                // Tooltip events
                circle.addEventListener("mouseenter", function (e) {
                    showTooltip(lbl, idx, xPos, yPos, data);
                });

                circle.addEventListener("mouseleave", function () {
                    hideTooltip();
                });

                svg.appendChild(circle);
            });
        });
    }

    function showTooltip(dateLabel, idx, xSvg, ySvg, data) {
        if (!tooltip) return;

        const crit = data.critical_series[idx] || 0;
        const hi = data.high_series[idx] || 0;
        const med = data.medium_series[idx] || 0;
        const lo = data.low_series[idx] || 0;

        tooltip.innerHTML = `
            <strong>${dateLabel}</strong>
            <div class="tooltip-row" style="color:#ff8593"><span>Critical:</span> <strong>${crit}</strong></div>
            <div class="tooltip-row" style="color:#ffb366"><span>High:</span> <strong>${hi}</strong></div>
            <div class="tooltip-row" style="color:#ffd24d"><span>Medium:</span> <strong>${med}</strong></div>
            <div class="tooltip-row" style="color:#66e0a3"><span>Low:</span> <strong>${lo}</strong></div>
        `;

        const rect = svg.getBoundingClientRect();
        const percentX = xSvg / 760;
        const percentY = ySvg / 300;

        const leftPx = percentX * rect.width;
        const topPx = percentY * rect.height;

        tooltip.style.left = `${leftPx}px`;
        tooltip.style.top = `${topPx}px`;
        tooltip.hidden = false;
    }

    function hideTooltip() {
        if (tooltip) {
            tooltip.hidden = true;
        }
    }
});
