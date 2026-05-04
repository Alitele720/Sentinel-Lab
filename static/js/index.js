(() => {
  const sqlForm = document.getElementById("sql-form");
  const xssForm = document.getElementById("xss-form");
  const labRoot = document.getElementById("bruteforce-lab");
  if (!sqlForm || !xssForm || !labRoot) {
    return;
  }

  const sqlSubmitButton = document.getElementById("sql-submit-button");
  const sqlFeedback = document.getElementById("sql-feedback");
  const sqlFeedbackTitle = document.getElementById("sql-feedback-title");
  const sqlFeedbackMessage = document.getElementById("sql-feedback-message");
  const sqlResultBox = document.getElementById("sql-result-box");
  const sqlQueryDisplay = document.getElementById("sql-query-display");

  const xssSubmitButton = document.getElementById("xss-submit-button");
  const xssFeedback = document.getElementById("xss-feedback");
  const xssFeedbackTitle = document.getElementById("xss-feedback-title");
  const xssFeedbackMessage = document.getElementById("xss-feedback-message");
  const xssSafeBox = document.getElementById("xss-safe-box");
  const xssSafeEcho = document.getElementById("xss-safe-echo");

  const demoIpInput = document.getElementById("bf-demo-ip");
  const manualForm = document.getElementById("bf-manual-form");
  const manualHiddenIp = manualForm.querySelector("[data-bf-hidden-ip]");
  const batchButtons = Array.from(document.querySelectorAll("[data-bf-action]"));
  const resetButton = document.getElementById("bf-reset-button");
  const feedback = document.getElementById("bf-feedback");
  const feedbackTitle = document.getElementById("bf-feedback-title");
  const feedbackMessage = document.getElementById("bf-feedback-message");
  const customCountInput = document.getElementById("bf-custom-count");

  const scanDemoIpInput = document.getElementById("scan-demo-ip");
  const scanButtons = Array.from(document.querySelectorAll(".scan-action-button"));
  const scanFeedback = document.getElementById("scan-feedback");
  const scanFeedbackTitle = document.getElementById("scan-feedback-title");
  const scanFeedbackMessage = document.getElementById("scan-feedback-message");
  const scanResultBox = document.getElementById("scan-result-box");
  const scanTargetPath = document.getElementById("scan-target-path");
  const scanStatusCode = document.getElementById("scan-status-code");
  const scanResponseSummary = document.getElementById("scan-response-summary");

  const stateNodes = {
    observeIp: document.getElementById("bf-observe-ip"),
    stagePill: document.getElementById("bf-stage-pill"),
    failureCount: document.getElementById("bf-failure-count"),
    windowMinutes: document.getElementById("bf-window-minutes"),
    lowThreshold: document.getElementById("bf-low-threshold"),
    highThreshold: document.getElementById("bf-high-threshold"),
    blockThreshold: document.getElementById("bf-block-threshold"),
    stageLabel: document.getElementById("bf-stage-label"),
    blockedText: document.getElementById("bf-blocked-text"),
    blockedRow: document.getElementById("bf-blocked-row"),
    blockedUntil: document.getElementById("bf-blocked-until"),
    latestSummary: document.getElementById("bf-latest-summary"),
    latestCreated: document.getElementById("bf-latest-created"),
    stageHint: document.getElementById("bf-stage-hint"),
    nextHint: document.getElementById("bf-next-hint"),
    criteriaLow: document.getElementById("bf-criteria-low"),
    criteriaHigh: document.getElementById("bf-criteria-high"),
    criteriaBlock: document.getElementById("bf-criteria-block"),
    blockNotice: document.getElementById("bf-block-notice"),
  };

  function setPanelFeedback(panel, titleNode, messageNode, message, tone, title) {
    panel.classList.remove("is-hidden", "feedback-success", "feedback-warning", "feedback-danger");
    panel.classList.add(`feedback-${tone}`);
    titleNode.textContent = title;
    messageNode.textContent = message;
  }

  function clearPanelFeedback(panel, titleNode, messageNode) {
    panel.classList.add("is-hidden");
    titleNode.textContent = "";
    messageNode.textContent = "";
  }

  function setButtonsDisabled(elements, disabled) {
    elements.forEach((element) => {
      element.disabled = disabled;
    });
  }

  function looksLikeDemoIp(value) {
    if (!value) {
      return false;
    }
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(value) || /^[0-9a-fA-F:]+$/.test(value);
  }

  function syncHiddenInputs() {
    if (manualHiddenIp) {
      manualHiddenIp.value = demoIpInput.value.trim();
    }
  }

  function setFeedback(message, tone = "warning", title = "实验结果") {
    setPanelFeedback(feedback, feedbackTitle, feedbackMessage, message, tone, title);
  }

  function clearFeedback() {
    clearPanelFeedback(feedback, feedbackTitle, feedbackMessage);
  }

  function renderState(state) {
    if (!state) {
      return;
    }

    stateNodes.observeIp.textContent = state.source_ip || "";
    stateNodes.failureCount.textContent = state.failure_count;
    stateNodes.windowMinutes.textContent = state.window_minutes;
    stateNodes.lowThreshold.textContent = state.low_threshold;
    stateNodes.highThreshold.textContent = state.high_threshold;
    stateNodes.blockThreshold.textContent = state.block_threshold;
    stateNodes.stageLabel.textContent = state.stage_label;
    stateNodes.blockedText.textContent = state.blocked ? "已封禁" : "未封禁";
    stateNodes.latestSummary.textContent = state.latest_summary || "当前还没有暴力破解告警。";
    stateNodes.latestCreated.textContent = state.latest_created_at_display || "";
    stateNodes.stageHint.textContent = state.stage_hint;
    stateNodes.nextHint.textContent = state.next_hint;
    stateNodes.criteriaLow.textContent = `${state.window_minutes} 分钟内失败 ${state.low_threshold} 次：低危告警`;
    stateNodes.criteriaHigh.textContent = `${state.window_minutes} 分钟内失败 ${state.high_threshold} 次：高危告警`;
    stateNodes.criteriaBlock.textContent = `${state.window_minutes} 分钟内失败 ${state.block_threshold} 次：自动加入黑名单`;
    stateNodes.stagePill.textContent = state.stage_label;
    stateNodes.stagePill.className = `status-pill status-${state.stage_key}`;

    if (state.blocked) {
      stateNodes.blockedRow.classList.remove("is-hidden");
      stateNodes.blockNotice.classList.remove("is-hidden");
      stateNodes.blockedUntil.textContent = state.blocked_until_display || "";
    } else {
      stateNodes.blockedRow.classList.add("is-hidden");
      stateNodes.blockNotice.classList.add("is-hidden");
      stateNodes.blockedUntil.textContent = "";
    }
  }

  async function requestJson(url, options = {}) {
    const response = await fetch(url, {
      ...options,
      headers: {
        Accept: "application/json",
        "X-Requested-With": "XMLHttpRequest",
        ...(options.headers || {}),
      },
    });

    const rawText = await response.text();
    let data = null;
    if (rawText) {
      try {
        data = JSON.parse(rawText);
      } catch (_error) {
        data = null;
      }
    }

    if (!response.ok) {
      const message = data && data.message ? data.message : "请求失败，请重试。";
      throw new Error(message);
    }
    return data;
  }

  async function requestTextResponse(url, options = {}) {
    const response = await fetch(url, {
      ...options,
      headers: {
        Accept: "text/plain, text/html, application/json",
        "X-Requested-With": "XMLHttpRequest",
        ...(options.headers || {}),
      },
    });

    const rawText = await response.text();
    const contentType = response.headers.get("content-type") || "";
    let data = null;
    if (contentType.includes("application/json")) {
      try {
        data = rawText ? JSON.parse(rawText) : null;
      } catch (_error) {
        data = null;
      }
    }

    return {
      ok: response.ok,
      status: response.status,
      text: rawText,
      data,
    };
  }

  async function refreshState(showError = false) {
    syncHiddenInputs();
    const demoIp = demoIpInput.value.trim();
    if (!demoIp) {
      return;
    }

    try {
      const url = `${labRoot.dataset.stateUrl}?demo_ip=${encodeURIComponent(demoIp)}`;
      const data = await requestJson(url);
      renderState(data.state);
    } catch (error) {
      if (showError) {
        setFeedback(error.message, "warning", "状态刷新失败");
      }
    }
  }

  function renderSqlResult(data) {
    sqlResultBox.classList.remove("is-hidden");
    sqlQueryDisplay.textContent = data.query || "";
  }

  function renderXssResult(data) {
    const hasContent = Boolean(data.message_text);
    xssSafeBox.classList.toggle("is-hidden", !hasContent);
    xssSafeEcho.textContent = data.safe_echo || "";
  }

  function renderScanResult(path, status, summary) {
    scanResultBox.classList.remove("is-hidden");
    scanTargetPath.textContent = path || "-";
    scanStatusCode.textContent = status ? String(status) : "-";
    scanResponseSummary.textContent = summary || "当前没有可显示的响应摘要。";
  }

  async function submitSqlForm() {
    setButtonsDisabled([sqlSubmitButton], true);
    try {
      const data = await requestJson(sqlForm.action, {
        method: "POST",
        body: new FormData(sqlForm),
      });
      renderSqlResult(data);
      setPanelFeedback(
        sqlFeedback,
        sqlFeedbackTitle,
        sqlFeedbackMessage,
        data.message || "SQL 测试已提交。",
        "success",
        data.title || "SQL 测试已提交"
      );
    } catch (error) {
      setPanelFeedback(sqlFeedback, sqlFeedbackTitle, sqlFeedbackMessage, error.message, "warning", "SQL 测试失败");
    } finally {
      setButtonsDisabled([sqlSubmitButton], false);
    }
  }

  async function submitXssForm() {
    setButtonsDisabled([xssSubmitButton], true);
    try {
      const data = await requestJson(xssForm.action, {
        method: "POST",
        body: new FormData(xssForm),
      });
      renderXssResult(data);
      setPanelFeedback(
        xssFeedback,
        xssFeedbackTitle,
        xssFeedbackMessage,
        data.message || "XSS 测试已提交。",
        "success",
        data.title || "XSS 测试已提交"
      );
    } catch (error) {
      setPanelFeedback(xssFeedback, xssFeedbackTitle, xssFeedbackMessage, error.message, "warning", "XSS 测试失败");
    } finally {
      setButtonsDisabled([xssSubmitButton], false);
    }
  }

  async function submitSimpleForm(form, titleOnError) {
    syncHiddenInputs();
    const formData = new FormData(form);
    if (!formData.get("demo_ip") && demoIpInput.value.trim()) {
      formData.set("demo_ip", demoIpInput.value.trim());
    }
    if (!formData.get("target_ip") && demoIpInput.value.trim()) {
      formData.set("target_ip", demoIpInput.value.trim());
    }

    try {
      const data = await requestJson(form.action, {
        method: "POST",
        body: formData,
      });
      renderState(data.state);
      setFeedback(data.message || "操作已完成。", data.state && data.state.blocked ? "danger" : "success", data.title || "操作成功");
    } catch (error) {
      setFeedback(error.message, "warning", titleOnError);
      await refreshState(false);
    }
  }

  async function handleScanAction(button) {
    const demoIp = scanDemoIpInput.value.trim();
    if (!demoIp) {
      setPanelFeedback(scanFeedback, scanFeedbackTitle, scanFeedbackMessage, "请先输入 demo_ip。", "warning", "输入校验失败");
      return;
    }
    if (!looksLikeDemoIp(demoIp)) {
      setPanelFeedback(scanFeedback, scanFeedbackTitle, scanFeedbackMessage, "请输入合法的 demo_ip，例如 10.10.10.99。", "warning", "输入校验失败");
      return;
    }

    setButtonsDisabled(scanButtons, true);
    const requestUrl = new URL(button.dataset.scanUrl, window.location.origin);
    requestUrl.searchParams.set("demo_ip", demoIp);

    try {
      const response = await requestTextResponse(requestUrl.toString());
      if (response.data && response.data.message) {
        setPanelFeedback(scanFeedback, scanFeedbackTitle, scanFeedbackMessage, response.data.message, "warning", "异常探测失败");
        return;
      }

      const summary = (response.text || "").trim() || "服务器没有返回额外文本。";
      renderScanResult(button.dataset.scanPath, response.status, summary);
      setPanelFeedback(
        scanFeedback,
        scanFeedbackTitle,
        scanFeedbackMessage,
        `${button.dataset.scanPath} 已探测，当前返回 ${response.status}。`,
        response.status === 403 ? "danger" : "success",
        "异常探测已提交"
      );
    } catch (_error) {
      setPanelFeedback(scanFeedback, scanFeedbackTitle, scanFeedbackMessage, "探测请求失败，请重试。", "warning", "异常探测失败");
    } finally {
      setButtonsDisabled(scanButtons, false);
    }
  }

  async function handleBatchAction(action) {
    const demoIp = demoIpInput.value.trim();
    if (!demoIp) {
      setFeedback("请先输入 demo_ip。", "warning", "输入校验失败");
      return;
    }

    const formData = new FormData();
    formData.set("demo_ip", demoIp);
    formData.set("action", action);

    if (action === "custom_count") {
      const count = Number(customCountInput.value);
      if (!Number.isInteger(count) || count < 1 || count > 50) {
        setFeedback("自定义次数必须在 1 到 50 之间。", "warning", "输入校验失败");
        return;
      }
      formData.set("count", String(count));
    }

    try {
      const data = await requestJson(labRoot.dataset.bruteforceUrl, {
        method: "POST",
        body: formData,
      });
      renderState(data.state);
      setFeedback(data.message || "操作已完成。", data.state && data.state.blocked ? "danger" : "success", data.title || "操作成功");
    } catch (error) {
      setFeedback(error.message, "warning", "操作失败");
      await refreshState(false);
    }
  }

  async function handleReset() {
    const demoIp = demoIpInput.value.trim();
    if (!demoIp) {
      setFeedback("请先输入需要重置的 demo_ip。", "warning", "输入校验失败");
      return;
    }

    const formData = new FormData();
    formData.set("target_ip", demoIp);

    try {
      const data = await requestJson(labRoot.dataset.resetUrl, {
        method: "POST",
        body: formData,
      });
      renderState(data.state);
      setFeedback(data.message || "当前实验已重置。", "success", data.title || "重置成功");
    } catch (error) {
      setFeedback(error.message, "warning", "重置失败");
      await refreshState(false);
    }
  }

  let refreshTimer = null;
  demoIpInput.addEventListener("input", () => {
    syncHiddenInputs();
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(() => {
      refreshState(false);
    }, 250);
  });

  demoIpInput.addEventListener("change", () => {
    syncHiddenInputs();
    refreshState(true);
  });

  sqlForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await submitSqlForm();
  });

  xssForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await submitXssForm();
  });

  manualForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await submitSimpleForm(manualForm, "手动登录失败");
  });

  batchButtons.forEach((button) => {
    button.addEventListener("click", async () => {
      await handleBatchAction(button.dataset.bfAction);
    });
  });

  resetButton.addEventListener("click", async () => {
    await handleReset();
  });

  scanButtons.forEach((button) => {
    button.addEventListener("click", async () => {
      await handleScanAction(button);
    });
  });

  if (!sqlFeedbackMessage.textContent.trim()) {
    clearPanelFeedback(sqlFeedback, sqlFeedbackTitle, sqlFeedbackMessage);
  }
  if (!xssFeedbackMessage.textContent.trim()) {
    clearPanelFeedback(xssFeedback, xssFeedbackTitle, xssFeedbackMessage);
  }
  clearPanelFeedback(scanFeedback, scanFeedbackTitle, scanFeedbackMessage);
  if (!feedbackMessage.textContent.trim()) {
    clearFeedback();
  }

  syncHiddenInputs();
})();
