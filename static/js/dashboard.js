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
        request_total: item.request_total,
        connection_total: item.connection_total,
      }));
    }
    if (Array.isArray(data.trafficByHour) && data.trafficByHour.length) {
      return data.trafficByHour.map((item) => ({
        time: item.hour,
        request_total: item.request_total,
        connection_total: item.connection_total,
      }));
    }
    return (data.requestsByHour || []).map((item) => ({
      time: item.hour,
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
    trafficChart.setOption({
      animationDurationUpdate: 600,
      animationEasingUpdate: "cubicOut",
      tooltip: { trigger: "axis" },
      legend: { data: ["Web 请求", "连接事件"] },
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
          name: "连接事件",
          type: "line",
          smooth: true,
          showSymbol: false,
          data: trafficSeries.map((item) => item.connection_total),
        },
      ],
    });
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
