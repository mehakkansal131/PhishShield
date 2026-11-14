"use strict";

(() => {
  const dataNode = document.getElementById("dashboard-data");
  if (!dataNode) return;

  let data;
  try {
    data = JSON.parse(dataNode.textContent);
  } catch (error) {
    console.error("Could not read dashboard chart data.", error);
    return;
  }

  const svgNamespace = "http://www.w3.org/2000/svg";
  const colors = {
    displayed: "#42d6c3",
    clicks: "#f0b968",
    reports: "#9b8cff",
  };

  function svgElement(name, attributes = {}, text = "") {
    const element = document.createElementNS(svgNamespace, name);
    Object.entries(attributes).forEach(([key, value]) => {
      element.setAttribute(key, String(value));
    });
    if (text) element.textContent = text;
    return element;
  }

  function createChart(containerId, label, width, height) {
    const container = document.getElementById(containerId);
    if (!container) return null;
    const svg = svgElement("svg", {
      viewBox: `0 0 ${width} ${height}`,
      role: "img",
      "aria-label": label,
      preserveAspectRatio: "xMinYMin meet",
    });
    svg.classList.add("dashboard-svg");
    container.replaceChildren(svg);
    return svg;
  }

  function addText(svg, x, y, value, className = "") {
    const text = svgElement("text", { x, y, class: className }, value);
    svg.appendChild(text);
    return text;
  }

  function addLegend(svg, items, startX, startY) {
    let x = startX;
    items.forEach((item) => {
      svg.appendChild(svgElement("rect", {
        x, y: startY - 11, width: 10, height: 10, fill: item.color, rx: 2,
      }));
      addText(svg, x + 15, startY - 2, item.label, "chart-legend");
      x += 125;
    });
  }

  function renderCampaignChart() {
    const rows = data.campaigns || [];
    if (!rows.length) return;
    const width = Math.max(680, rows.length * 150 + 90);
    const height = 300;
    const svg = createChart(
      "campaign-chart",
      "Bars compare display event totals, unique clickers, and unique reporters for each campaign.",
      width,
      height,
    );
    if (!svg) return;

    const top = 36;
    const bottom = height - 58;
    const plotHeight = bottom - top;
    const maxValue = Math.max(1, ...rows.flatMap((row) => [
      row.display_events, row.unique_clicked, row.unique_reported,
    ]));
    const groupWidth = (width - 100) / rows.length;
    const series = [
      { key: "display_events", color: colors.displayed },
      { key: "unique_clicked", color: colors.clicks },
      { key: "unique_reported", color: colors.reports },
    ];

    for (let tick = 0; tick <= 4; tick += 1) {
      const value = Math.ceil((maxValue / 4) * tick);
      const y = bottom - (plotHeight * tick) / 4;
      svg.appendChild(svgElement("line", {
        x1: 56, y1: y, x2: width - 18, y2: y, class: "chart-gridline",
      }));
      addText(svg, 8, y + 4, String(value), "chart-axis-label");
    }

    rows.forEach((row, index) => {
      const center = 70 + groupWidth * index + groupWidth / 2;
      const barWidth = Math.min(24, (groupWidth - 24) / 3);
      series.forEach((item, seriesIndex) => {
        const value = row[item.key];
        const barHeight = (value / maxValue) * plotHeight;
        const x = center - 1.5 * barWidth + seriesIndex * barWidth;
        const y = bottom - barHeight;
        const bar = svgElement("rect", {
          x, y, width: Math.max(8, barWidth - 4), height: Math.max(0, barHeight),
          fill: item.color, rx: 3,
        });
        bar.appendChild(svgElement(
          "title",
          {},
          `${row.campaign_name}: ${item.key.replaceAll("_", " ")} ${value}`,
        ));
        svg.appendChild(bar);
      });
      addText(svg, center, bottom + 20, row.campaign_name.slice(0, 18), "chart-axis-label chart-x-label");
    });
    addLegend(svg, [
      { label: "Displays", color: colors.displayed },
      { label: "Unique clicks", color: colors.clicks },
      { label: "Unique reports", color: colors.reports },
    ], 65, height - 10);
  }

  function renderRateChart(containerId, rows, labelField, labelValue) {
    if (!rows.length) return;
    const width = Math.max(680, rows.length * 150 + 90);
    const height = 300;
    const svg = createChart(containerId, labelValue, width, height);
    if (!svg) return;

    const top = 36;
    const bottom = height - 58;
    const plotHeight = bottom - top;
    const groupWidth = (width - 100) / rows.length;
    const maxRate = Math.max(
      100,
      Math.ceil(Math.max(...rows.flatMap((row) => [
        row.click_rate, row.report_rate,
      ])) / 25) * 25,
    );
    for (let tick = 0; tick <= 4; tick += 1) {
      const value = (maxRate / 4) * tick;
      const scaledY = bottom - (plotHeight * value) / maxRate;
      svg.appendChild(svgElement("line", {
        x1: 56, y1: scaledY, x2: width - 18, y2: scaledY, class: "chart-gridline",
      }));
      addText(svg, 8, scaledY + 4, `${value.toFixed(0)}%`, "chart-axis-label");
    }

    rows.forEach((row, index) => {
      const center = 70 + groupWidth * index + groupWidth / 2;
      const barWidth = Math.min(32, (groupWidth - 20) / 2);
      [
        { key: "click_rate", color: colors.clicks },
        { key: "report_rate", color: colors.reports },
      ].forEach((item, seriesIndex) => {
        const rate = row[item.key];
        const barHeight = (rate / maxRate) * plotHeight;
        const x = center - barWidth + seriesIndex * barWidth;
        const y = bottom - barHeight;
        const bar = svgElement("rect", {
          x, y, width: Math.max(8, barWidth - 4), height: Math.max(0, barHeight),
          fill: item.color, rx: 3,
        });
        bar.appendChild(svgElement(
          "title",
          {},
          `${row[labelField]}: ${item.key === "click_rate" ? "click" : "report"} rate ${rate.toFixed(1)}%`,
        ));
        svg.appendChild(bar);
      });
      addText(svg, center, bottom + 20, String(row[labelField]).slice(0, 18), "chart-axis-label chart-x-label");
    });
    addLegend(svg, [
      { label: "Click rate", color: colors.clicks },
      { label: "Report rate", color: colors.reports },
    ], 135, height - 10);
  }

  function renderTimeline() {
    const timeline = data.timeline;
    if (!timeline || !timeline.available || !timeline.days.length) return;
    const rows = timeline.days;
    const width = Math.max(720, rows.length * 26 + 80);
    const height = 300;
    const svg = createChart(
      "timeline-chart",
      "Daily displayed, clicked, and reported event counts across the latest thirty valid event dates.",
      width,
      height,
    );
    if (!svg) return;
    const top = 38;
    const bottom = height - 58;
    const left = 55;
    const right = width - 20;
    const plotHeight = bottom - top;
    const plotWidth = right - left;
    const maxValue = Math.max(1, ...rows.flatMap((row) => [
      row.displayed, row.clicked, row.reported,
    ]));

    for (let tick = 0; tick <= 4; tick += 1) {
      const value = Math.ceil((maxValue / 4) * tick);
      const y = bottom - (plotHeight * tick) / 4;
      svg.appendChild(svgElement("line", {
        x1: left, y1: y, x2: right, y2: y, class: "chart-gridline",
      }));
      addText(svg, 8, y + 4, String(value), "chart-axis-label");
    }

    [
      { key: "displayed", color: colors.displayed },
      { key: "clicked", color: colors.clicks },
      { key: "reported", color: colors.reports },
    ].forEach((series) => {
      const points = rows.map((row, index) => {
        const x = left + (plotWidth * index) / Math.max(1, rows.length - 1);
        const y = bottom - (row[series.key] / maxValue) * plotHeight;
        return { x, y, row };
      });
      const pathData = points.map((point, index) =>
        `${index === 0 ? "M" : "L"} ${point.x} ${point.y}`,
      ).join(" ");
      svg.appendChild(svgElement("path", {
        d: pathData, fill: "none", stroke: series.color, "stroke-width": 2.5,
      }));
      points.forEach((point) => {
        const circle = svgElement("circle", {
          cx: point.x, cy: point.y, r: 3, fill: series.color,
        });
        circle.appendChild(svgElement(
          "title",
          {},
          `${point.row.date}: ${series.key} ${point.row[series.key]}`,
        ));
        svg.appendChild(circle);
      });
    });
    rows.forEach((row, index) => {
      if (index % 5 === 0 || index === rows.length - 1) {
        const x = left + (plotWidth * index) / Math.max(1, rows.length - 1);
        addText(svg, x, bottom + 20, row.date.slice(5), "chart-axis-label chart-x-label");
      }
    });
    addLegend(svg, [
      { label: "Displayed", color: colors.displayed },
      { label: "Clicked", color: colors.clicks },
      { label: "Reported", color: colors.reports },
    ], 90, height - 10);
  }

  renderCampaignChart();
  renderRateChart(
    "rate-chart",
    data.campaigns || [],
    "campaign_name",
    "Click-through and report rate by campaign, using unique displayed participants as denominator.",
  );
  renderRateChart(
    "scenario-chart",
    data.scenarios || [],
    "scenario",
    "Click-through and report rates by scenario, using unique displayed participants as denominator.",
  );
  renderTimeline();
})();
