(() => {
  const root = document.getElementById("dashboard-root");
  if (!root) {
    return;
  }

  const REFRESH_INTERVAL_MS = 2000;
  let trafficChart = null;
  let attacksChart = null;
  let ipsChart = null;
  let refreshTimer = null;
  let pollInFlight = false;

  function showChartError(message) {
    document.querySelectorAll(".chart").forEach((node) => {
      if (!node.dataset.hasChartError) {
        node.insertAdjacentHTML("beforeend", `<p class="tip">${message}</p>`);
        node.dataset.hasChartError = "1";
      }
    });
  }

  function clearChartError() {
    document.querySelectorAll(".chart").forEach((node) => {
      node.querySelectorAll(".tip").forEach((tip) => tip.remove());
      delete node.dataset.hasChartError;
    });
  }

  function buildTrafficSeries(data) {
    if (Array.isArray(data.trafficRealtime) && data.trafficRealtime.length) {
      return data.trafficRealtime.map((item) => ({
        time: item.time.slice(3),
        full_time: item.time,
        request_total: item.request_total,
        connection_total: item.connection_total,
      }));
    }
    if (Array.isArray(data.trafficByHour) && data.trafficByHour.length) {
      return data.trafficByHour.map((item) => ({
        time: item.hour,
        full_time: item.hour,
        request_total: item.request_total,
        connection_total: item.connection_total,
      }));
    }
    return (data.requestsByHour || []).map((item) => ({
      time: item.hour,
      full_time: item.hour,
      request_total: item.total,
      connection_total: 0,
    }));
  }

  function ensureCharts() {
    if (!window.echarts) {
      showChartError("图表暂不可用。");
      return false;
    }
    clearChartError();
    if (!trafficChart) {
      trafficChart = window.echarts.init(document.getElementById("requests-chart"));
    }
    if (!attacksChart) {
      attacksChart = window.echarts.init(document.getElementById("attacks-chart"));
    }
    if (!ipsChart) {
      ipsChart = window.echarts.init(document.getElementById("ips-chart"));
    }
    return true;
  }

  function updateTrafficChart(data) {
    const trafficSeries = buildTrafficSeries(data);
    const hasConnectionTraffic = trafficSeries.some((item) => item.connection_total > 0);
    trafficChart.setOption({
      animationDurationUpdate: 600,
      animationEasingUpdate: "cubicOut",
      color: ["#5470c6", "#0b8f6a"],
      tooltip: {
        trigger: "axis",
        formatter(params) {
          const index = params[0]?.dataIndex || 0;
          const point = trafficSeries[index] || {};
          const rows = params.map((item) => `${item.marker}${item.seriesName}: ${item.value}`);
          return [`时间：${point.full_time || point.time}`, ...rows].join("<br>");
        },
      },
      legend: { data: ["Web 请求", "TCP 探测"] },
      xAxis: { type: "category", boundaryGap: false, data: trafficSeries.map((item) => item.time) },
      yAxis: { type: "value" },
      series: [
        {
          name: "Web 请求",
          type: "line",
          smooth: true,
          showSymbol: false,
          data: trafficSeries.map((item) => item.request_total),
          areaStyle: {},
        },
        {
          name: "TCP 探测",
          type: "line",
          smooth: true,
          showSymbol: hasConnectionTraffic,
          data: trafficSeries.map((item) => item.connection_total),
          lineStyle: { width: 3, type: hasConnectionTraffic ? "solid" : "dashed" },
          areaStyle: { opacity: hasConnectionTraffic ? 0.12 : 0 },
        },
      ],
    });
  }

  function renderRankList(nodeId, rows, emptyText, formatLabel) {
    const node = document.getElementById(nodeId);
    if (!node) {
      return;
    }
    if (!Array.isArray(rows) || !rows.length) {
      node.innerHTML = `<li class="empty">${emptyText}</li>`;
      return;
    }
    node.innerHTML = rows
      .map((row) => `<li><span>${formatLabel(row)}</span><strong>${row.total}</strong></li>`)
      .join("");
  }

  function updateTrafficIntel(data) {
    const capture = data.captureStatus || {};
    const summary = data.recentConnectionSummary || {};
    const alerts = data.recentPortScanAlerts || {};
    const statusNode = document.getElementById("capture-status");
    const detailNode = document.getElementById("capture-detail");
    const summaryNode = document.getElementById("connection-summary");
    const alertNode = document.getElementById("portscan-alert-summary");
    const emptyNode = document.getElementById("connection-empty-state");
    if (statusNode) {
      statusNode.textContent = `真实抓包：${capture.label || "未知"}`;
      statusNode.dataset.state = capture.state || "unknown";
    }
    if (detailNode) {
      if (capture.enabled) {
        detailNode.textContent = `接口：${capture.interface || "默认网卡"} / 过滤器：${capture.filter || "tcp"}`;
      } else {
        detailNode.textContent = "真实抓包未启用，连接事件可能来自实验管线。";
      }
    }
    if (summaryNode) {
      summaryNode.textContent = `TCP 探测 ${summary.total || 0} 次 / ${summary.unique_sources || 0} 个来源 / ${summary.unique_target_ports || 0} 个端口`;
    }
    if (alertNode) {
      const severity = alerts.highest_severity ? `，最高 ${alerts.highest_severity}` : "";
      alertNode.textContent = `端口扫描告警 ${alerts.total || 0} 条${severity}`;
    }
    if (emptyNode) {
      emptyNode.hidden = Boolean(summary.total);
    }
    renderRankList("top-connection-sources", data.topConnectionSources, "暂无来源", (row) => row.ip);
    renderRankList("top-target-ports", data.topTargetPorts, "暂无端口", (row) => `TCP/${row.port}`);
  }

  function updateStaticCharts(data) {
    attacksChart.setOption({
      tooltip: { trigger: "item" },
      series: [
        {
          type: "pie",
          radius: ["40%", "70%"],
          data: data.attacksByType.map((item) => ({ name: item.type, value: item.total })),
        },
      ],
    });

    ipsChart.setOption({
      tooltip: { trigger: "axis" },
      xAxis: { type: "value" },
      yAxis: { type: "category", data: data.topAttackIps.map((item) => item.ip) },
      series: [{ type: "bar", data: data.topAttackIps.map((item) => item.total) }],
    });
  }

  async function fetchStats() {
    const response = await fetch(root.dataset.statsUrl, {
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    if (!response.ok) {
      throw new Error(`stats request failed: ${response.status}`);
    }
    return response.json();
  }

  async function refreshTrafficChart() {
    if (pollInFlight) {
      return;
    }
    pollInFlight = true;
    try {
      const data = await fetchStats();
      if (!ensureCharts()) {
        return;
      }
      updateTrafficChart(data);
      updateTrafficIntel(data);
      if (!attacksChart.getOption().series) {
        updateStaticCharts(data);
      }
    } catch (_error) {
      showChartError("图表加载失败，请刷新重试。");
    } finally {
      pollInFlight = false;
    }
  }

  async function initialize() {
    const data = await fetchStats();
    if (!ensureCharts()) {
      return;
    }
    updateTrafficChart(data);
    updateTrafficIntel(data);
    updateStaticCharts(data);
  }

  function scheduleRefresh() {
    clearInterval(refreshTimer);
    refreshTimer = setInterval(() => {
      refreshTrafficChart();
    }, REFRESH_INTERVAL_MS);
  }

  function cleanup() {
    clearInterval(refreshTimer);
    refreshTimer = null;
    if (trafficChart) {
      trafficChart.dispose();
      trafficChart = null;
    }
    if (attacksChart) {
      attacksChart.dispose();
      attacksChart = null;
    }
    if (ipsChart) {
      ipsChart.dispose();
      ipsChart = null;
    }
  }

  initialize()
    .catch(() => {
      showChartError("图表加载失败，请刷新重试。");
    })
    .finally(() => {
      scheduleRefresh();
    });

  window.addEventListener("beforeunload", cleanup);
})();
