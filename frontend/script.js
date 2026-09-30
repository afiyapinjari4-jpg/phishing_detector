/* ==========================================================================
   PhishGuard - SOC Dashboard, Radar Analytics & Dynamic Telemetry
   ========================================================================== */

const API_BASE = "http://127.0.0.1:8000";

const KNOWN_GROUND_TRUTH = {
  "https://www.google.com": false,
  "https://en.wikipedia.org/wiki/Machine_learning": false,
  "https://in.pinterest.com/": false,
  "https://web.whatsapp.com/": false,
  "http://192.168.1.105/paypal/login": true,
  "http://secure-login.paypal.com.account-update.ru/login.php": true
};

const DEFAULT_HISTORY = [
  { id: 1, url: "https://www.google.com", result: "Legitimate", is_phish: false, actual_is_phish: false, confidence: 99.2, time: "10:24 AM", tier: "Trusted Domain Authority Check", features: { has_suspicious_words: 0, count_hyphens: 0, has_ip_address: 0, is_shortened: 0, count_special_chars: 0, url_length: 22, count_subdomains: 0 } },
  { id: 2, url: "https://en.wikipedia.org/wiki/Machine_learning", result: "Legitimate", is_phish: false, actual_is_phish: false, confidence: 90.7, time: "10:18 AM", tier: "Random Forest Classifier", features: { has_suspicious_words: 0, count_hyphens: 0, has_ip_address: 0, is_shortened: 0, count_special_chars: 0, url_length: 46, count_subdomains: 0 } },
  { id: 3, url: "https://in.pinterest.com/", result: "Legitimate", is_phish: false, actual_is_phish: false, confidence: 99.2, time: "10:15 AM", tier: "Trusted Domain Authority Check", features: { has_suspicious_words: 0, count_hyphens: 0, has_ip_address: 0, is_shortened: 0, count_special_chars: 0, url_length: 25, count_subdomains: 1 } },
  { id: 4, url: "http://192.168.1.105/paypal/login", result: "Malicious", is_phish: true, actual_is_phish: true, confidence: 98.4, time: "10:12 AM", tier: "Random Forest Classifier", features: { has_suspicious_words: 1, count_hyphens: 0, has_ip_address: 1, is_shortened: 0, count_special_chars: 0, url_length: 33, count_subdomains: 0 } },
  { id: 5, url: "http://secure-login.paypal.com.account-update.ru/login.php", result: "Malicious", is_phish: true, actual_is_phish: true, confidence: 97.8, time: "10:08 AM", tier: "Random Forest Classifier", features: { has_suspicious_words: 1, count_hyphens: 2, has_ip_address: 0, is_shortened: 0, count_special_chars: 0, url_length: 58, count_subdomains: 3 } }
];

function getScanHistory() {
  const data = localStorage.getItem("phishguard_history");
  if (!data) {
    localStorage.setItem("phishguard_history", JSON.stringify(DEFAULT_HISTORY));
    return DEFAULT_HISTORY;
  }
  return JSON.parse(data);
}

function saveScanHistory(list) {
  localStorage.setItem("phishguard_history", JSON.stringify(list));
}

let threatDonutChart = null;
let attackRadarChart = null;
let trendLineChart = null;
let topThreatDonut = null;
let modelBarChart = null;

document.addEventListener("DOMContentLoaded", () => {
  setupNavigation();
  setupQuickButtons();
  setupInspectors();
  startCyberClock();
  initializeCharts();
  refreshAllDynamicData();
  checkBackendHealth();
});

function startCyberClock() {
  const clockEl = document.getElementById("live-cyber-clock");
  const updateTime = () => {
    const now = new Date();
    if (clockEl) {
      clockEl.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
  };
  updateTime();
  setInterval(updateTime, 1000);
}

function setupNavigation() {
  const navItems = document.querySelectorAll(".nav-item");
  const views = document.querySelectorAll(".tab-view");
  const titleEl = document.getElementById("current-view-title");

  const titles = {
    "dashboard": "Command Center Overview",
    "scan-url": "Interactive URL Inspector",
    "scan-history": "Persistent Scan Logs",
    "model-info": "Model Architecture & Confusion Matrix",
    "analytics": "Real-time Telemetry & Diagnostics",
    "settings": "System Parameters",
    "about": "Project Documentation"
  };

  navItems.forEach((btn) => {
    btn.addEventListener("click", () => {
      const tabName = btn.getAttribute("data-tab");

      navItems.forEach((n) => n.classList.remove("active"));
      views.forEach((v) => v.classList.remove("active"));

      btn.classList.add("active");
      const targetView = document.getElementById(`view-${tabName}`);
      if (targetView) targetView.classList.add("active");
      if (titleEl && titles[tabName]) titleEl.textContent = titles[tabName];
    });
  });

  document.getElementById("dash-scan-now-btn")?.addEventListener("click", () => switchTab("scan-url"));

  document.getElementById("clear-history-btn")?.addEventListener("click", () => {
    saveScanHistory([]);
    refreshAllDynamicData();
  });
}

function switchTab(tabId) {
  const navBtn = document.querySelector(`.nav-item[data-tab="${tabId}"]`);
  if (navBtn) navBtn.click();
}

function setupQuickButtons() {
  const testButtons = document.querySelectorAll("[data-test]");
  testButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const testUrl = btn.getAttribute("data-test");
      executeScan(testUrl);
    });
  });
}

function setupInspectors() {
  const inspectorInput = document.getElementById("inspector-url-input");
  const inspectorBtn = document.getElementById("inspector-scan-btn");

  if (inspectorBtn) {
    inspectorBtn.addEventListener("click", () => {
      if (inspectorInput && inspectorInput.value.trim()) executeScan(inspectorInput.value.trim());
    });
  }

  if (inspectorInput) {
    inspectorInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && inspectorInput.value.trim()) executeScan(inspectorInput.value.trim());
    });
  }
}

async function executeScan(url) {
  switchTab("scan-url");

  const inspectorInput = document.getElementById("inspector-url-input");
  if (inspectorInput) inspectorInput.value = url;

  const resultContainer = document.getElementById("inspector-result-panel");
  if (resultContainer) {
    resultContainer.className = "panel";
    resultContainer.innerHTML = `
      <div style="text-align:center; padding: 20px;">
        <span style="color: var(--accent-cyan); font-weight:600;">Analyzing URL heuristics & running Random Forest inference...</span>
      </div>
    `;
  }

  const startTime = performance.now();

  try {
    const response = await fetch(`${API_BASE}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: url })
    });

    const elapsedMs = Math.round(performance.now() - startTime);
    const pingEl = document.getElementById("backend-ping");
    if (pingEl) pingEl.textContent = `Response Time: ${elapsedMs}ms`;

    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const data = await response.json();
    renderInspectorResult(data);

    let actualTruth = KNOWN_GROUND_TRUTH[data.url];
    if (actualTruth === undefined) {
      actualTruth = data.is_phishing;
    }

    const history = getScanHistory();
    const now = new Date();
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    history.unshift({
      id: Date.now(),
      url: data.url,
      result: data.is_phishing ? "Malicious" : "Legitimate",
      is_phish: data.is_phishing,
      actual_is_phish: actualTruth,
      confidence: data.confidence,
      time: timeStr,
      tier: data.tier || "Random Forest Classifier",
      features: data.features || {}
    });

    saveScanHistory(history);
    refreshAllDynamicData();

  } catch (err) {
    if (resultContainer) {
      resultContainer.innerHTML = `
        <div style="padding: 16px; border: 1px solid var(--accent-red); border-radius: 8px; background: rgba(239,68,68,0.1);">
          <strong style="color: var(--accent-red);">Scan Error:</strong>
          <p style="font-size: 0.84rem; color: #fff; margin-top: 4px;">Failed connecting to FastAPI backend at <code>${API_BASE}</code>.</p>
        </div>
      `;
    }
  }
}

window.verifyGroundTruth = function(id, trueLabel) {
  const history = getScanHistory();
  const entry = history.find(item => item.id === id);
  if (entry) {
    entry.actual_is_phish = (trueLabel === 'malicious');
    saveScanHistory(history);
    refreshAllDynamicData();
  }
};

function refreshAllDynamicData() {
  const history = getScanHistory();
  renderHistoryTable(history);
  updateDynamicMetricsAndCharts(history);
}

function updateDynamicMetricsAndCharts(history) {
  const total = history.length;
  const malCount = history.filter(h => h.is_phish).length;
  const legitCount = total - malCount;
  const legitPct = total > 0 ? Math.round((legitCount / total) * 100) : 100;
  const malPct = total > 0 ? Math.round((malCount / total) * 100) : 0;

  // 1. Dashboard Threat Ratio & Severity Meter
  const innerPctEl = document.querySelector(".inner-pct");
  const countLegitEl = document.getElementById("dash-count-legit");
  const countMalEl = document.getElementById("dash-count-mal");
  const severityVal = document.getElementById("severity-val");
  const severityBar = document.getElementById("severity-bar");
  const postureBadge = document.getElementById("posture-badge");

  if (innerPctEl) innerPctEl.textContent = `${legitPct}%`;
  if (countLegitEl) countLegitEl.textContent = legitCount;
  if (countMalEl) countMalEl.textContent = malCount;

  if (severityVal && severityBar) {
    severityBar.style.width = `${Math.max(10, malPct)}%`;
    if (malPct > 40) {
      severityVal.textContent = `ELEVATED (${malPct}%)`;
      severityVal.style.color = "var(--accent-red)";
      severityBar.style.background = "linear-gradient(90deg, #f59e0b, #ef4444)";
      if (postureBadge) {
        postureBadge.textContent = "STATUS: ELEVATED";
        postureBadge.style.color = "var(--accent-red)";
        postureBadge.style.borderColor = "var(--accent-red)";
      }
    } else {
      severityVal.textContent = `NOMINAL (${malPct}%)`;
      severityVal.style.color = "var(--accent-emerald)";
      severityBar.style.background = "linear-gradient(90deg, #10b981, #06b6d4)";
      if (postureBadge) {
        postureBadge.textContent = "STATUS: NOMINAL";
        postureBadge.style.color = "var(--accent-emerald)";
        postureBadge.style.borderColor = "var(--accent-emerald)";
      }
    }
  }

  if (threatDonutChart) {
    threatDonutChart.data.datasets[0].data = [legitCount || 1, malCount || 0];
    threatDonutChart.update();
  }

  // 2. Attack Vector Radar Dynamic Calculation
  let radarVectors = { keywords: 0, subdomains: 0, hyphens: 0, ip: 0, special: 0, length: 0 };
  const maliciousItems = history.filter(h => h.is_phish);

  maliciousItems.forEach(item => {
    const f = item.features || {};
    if (f.has_suspicious_words > 0) radarVectors.keywords += 25;
    if (f.count_subdomains > 1) radarVectors.subdomains += 20;
    if (f.count_hyphens > 0) radarVectors.hyphens += 20;
    if (f.has_ip_address > 0) radarVectors.ip += 30;
    if (f.count_special_chars > 0) radarVectors.special += 15;
    if (f.url_length > 40) radarVectors.length += 15;
  });

  if (attackRadarChart) {
    attackRadarChart.data.datasets[0].data = [
      Math.min(100, radarVectors.keywords + 30),
      Math.min(100, radarVectors.subdomains + 20),
      Math.min(100, radarVectors.hyphens + 25),
      Math.min(100, radarVectors.ip + 15),
      Math.min(100, radarVectors.special + 20),
      Math.min(100, radarVectors.length + 35)
    ];
    attackRadarChart.update();
  }

  // 3. Analytics View Counters
  const statTotalEl = document.querySelector("#view-analytics .stat-card:nth-child(1) h3");
  const statMalEl = document.querySelector("#view-analytics .stat-card:nth-child(2) h3");
  const statLegitEl = document.querySelector("#view-analytics .stat-card:nth-child(3) h3");
  const statMalBadge = document.querySelector(".stat-badge-red");
  const statLegitBadge = document.querySelector(".stat-badge-cyan");

  if (statTotalEl) statTotalEl.textContent = total;
  if (statMalEl) statMalEl.textContent = malCount;
  if (statLegitEl) statLegitEl.textContent = legitCount;
  if (statMalBadge) statMalBadge.textContent = `${total > 0 ? ((malCount / total) * 100).toFixed(1) : 0}% of total`;
  if (statLegitBadge) statLegitBadge.textContent = `${total > 0 ? ((legitCount / total) * 100).toFixed(1) : 0}% of total`;

  // 4. Scan Results Trend
  if (trendLineChart) {
    const runningLegit = [];
    const runningMal = [];
    const labels = [];
    let curLegit = 0;
    let curMal = 0;

    const chronological = [...history].reverse();
    chronological.forEach((item, idx) => {
      if (item.is_phish) curMal++;
      else curLegit++;

      labels.push(`Scan #${idx + 1}`);
      runningLegit.push(curLegit);
      runningMal.push(curMal);
    });

    trendLineChart.data.labels = labels.length > 0 ? labels : ["Start"];
    trendLineChart.data.datasets[0].data = runningLegit.length > 0 ? runningLegit : [0];
    trendLineChart.data.datasets[1].data = runningMal.length > 0 ? runningMal : [0];
    trendLineChart.update();
  }

  // 5. Session Precision, Recall & F1
  let tp = 0, tn = 0, fp = 0, fn = 0;
  history.forEach(item => {
    const pred = item.is_phish;
    const actual = item.actual_is_phish;
    if (pred === true && actual === true) tp++;
    else if (pred === false && actual === false) tn++;
    else if (pred === true && actual === false) fp++;
    else if (pred === false && actual === true) fn++;
  });

  const safeDiv = (num, den) => den === 0 ? 0.95 : +(num / den).toFixed(2);

  const precPhish = safeDiv(tp, tp + fp);
  const recPhish = safeDiv(tp, tp + fn);
  const f1Phish = (precPhish + recPhish) === 0 ? 0.95 : +(2 * (precPhish * recPhish) / (precPhish + recPhish)).toFixed(2);

  const precLegit = safeDiv(tn, tn + fn);
  const recLegit = safeDiv(tn, tn + fp);
  const f1Legit = (precLegit + recLegit) === 0 ? 0.95 : +(2 * (precLegit * recLegit) / (precLegit + recLegit)).toFixed(2);

  if (modelBarChart) {
    modelBarChart.data.datasets[0].data = [precLegit, precPhish];
    modelBarChart.data.datasets[1].data = [recLegit, recPhish];
    modelBarChart.data.datasets[2].data = [f1Legit, f1Phish];
    modelBarChart.update();
  }

  const avgPrec = +((precLegit + precPhish) / 2).toFixed(2);
  const avgRec = +((recLegit + recPhish) / 2).toFixed(2);
  const avgF1 = +((f1Legit + f1Phish) / 2).toFixed(2);
  const gaugePrec = document.querySelector(".gauge-blue span");
  const gaugeRec = document.querySelector(".gauge-purple span");
  const gaugeF1 = document.querySelector(".gauge-teal span");
  if (gaugePrec) gaugePrec.textContent = avgPrec;
  if (gaugeRec) gaugeRec.textContent = avgRec;
  if (gaugeF1) gaugeF1.textContent = avgF1;

  // 6. Threat Indicator Distribution
  let featCounts = { words: 0, hyphens: 0, ip: 0, short: 0, special: 0, length: 0 };
  maliciousItems.forEach(item => {
    const f = item.features || {};
    if (f.has_suspicious_words > 0) featCounts.words++;
    if (f.count_hyphens > 0) featCounts.hyphens++;
    if (f.has_ip_address > 0) featCounts.ip++;
    if (f.is_shortened > 0) featCounts.short++;
    if (f.count_special_chars > 0) featCounts.special++;
    if (f.url_length > 40) featCounts.length++;
  });

  const sumFeats = Object.values(featCounts).reduce((a, b) => a + b, 0) || 1;
  const pWords = Math.round((featCounts.words / sumFeats) * 100);
  const pHyphens = Math.round((featCounts.hyphens / sumFeats) * 100);
  const pIP = Math.round((featCounts.ip / sumFeats) * 100);
  const pShort = Math.round((featCounts.short / sumFeats) * 100);
  const pSpecial = Math.round((featCounts.special / sumFeats) * 100);
  const pLength = Math.round((featCounts.length / sumFeats) * 100);

  const innerThreatCount = document.querySelector(".donut-inner-threat strong");
  if (innerThreatCount) innerThreatCount.textContent = malCount;

  const wEl = document.getElementById("lbl-threat-words");
  const hEl = document.getElementById("lbl-threat-hyphens");
  const ipEl = document.getElementById("lbl-threat-ip");
  const sEl = document.getElementById("lbl-threat-short");
  const spEl = document.getElementById("lbl-threat-special");
  const lEl = document.getElementById("lbl-threat-length");

  if (wEl) wEl.textContent = `${pWords}%`;
  if (hEl) hEl.textContent = `${pHyphens}%`;
  if (ipEl) ipEl.textContent = `${pIP}%`;
  if (sEl) sEl.textContent = `${pShort}%`;
  if (spEl) spEl.textContent = `${pSpecial}%`;
  if (lEl) lEl.textContent = `${pLength}%`;

  if (topThreatDonut) {
    topThreatDonut.data.datasets[0].data = [pWords || 1, pHyphens || 1, pIP || 1, pShort || 1, pSpecial || 1, pLength || 1];
    topThreatDonut.update();
  }

  const contribBars = document.querySelector(".bar-contrib-list");
  if (contribBars) {
    contribBars.innerHTML = `
      <div class="contrib-row">
        <span class="contrib-name">Suspicious Words</span>
        <div class="contrib-track"><div class="contrib-bar c-blue" style="width: ${Math.max(5, pWords)}%;"></div></div>
        <span class="contrib-val">${pWords}%</span>
      </div>
      <div class="contrib-row">
        <span class="contrib-name">Hyphens</span>
        <div class="contrib-track"><div class="contrib-bar c-teal" style="width: ${Math.max(5, pHyphens)}%;"></div></div>
        <span class="contrib-val">${pHyphens}%</span>
      </div>
      <div class="contrib-row">
        <span class="contrib-name">IP Address</span>
        <div class="contrib-track"><div class="contrib-bar c-cyan" style="width: ${Math.max(5, pIP)}%;"></div></div>
        <span class="contrib-val">${pIP}%</span>
      </div>
      <div class="contrib-row">
        <span class="contrib-name">URL Length (>40)</span>
        <div class="contrib-track"><div class="contrib-bar c-red" style="width: ${Math.max(5, pLength)}%;"></div></div>
        <span class="contrib-val">${pLength}%</span>
      </div>
      <div class="contrib-row">
        <span class="contrib-name">Special Chars</span>
        <div class="contrib-track"><div class="contrib-bar c-orange" style="width: ${Math.max(5, pSpecial)}%;"></div></div>
        <span class="contrib-val">${pSpecial}%</span>
      </div>
    `;
  }
}

function renderHistoryTable(history) {
  const fullTbody = document.getElementById("full-history-tbody");
  if (fullTbody) {
    if (history.length === 0) {
      fullTbody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding: 24px;">No URLs scanned yet.</td></tr>`;
    } else {
      fullTbody.innerHTML = history.map(item => `
        <tr>
          <td class="table-url-cell" title="${item.url}">${item.url}</td>
          <td><span class="${item.is_phish ? 'badge-phish' : 'badge-legit'}">${item.result}</span></td>
          <td><strong>${item.confidence}%</strong></td>
          <td><span style="font-size:0.75rem; color:var(--text-muted);">${item.tier}</span></td>
          <td>${item.time}</td>
          <td>
            <button class="pill-btn pill-blue" onclick="executeScan('${item.url}')">Re-scan</button>
            <button class="pill-btn pill-purple" title="Correct Label" onclick="window.verifyGroundTruth(${item.id}, '${item.is_phish ? "legitimate" : "malicious"}')">Invert</button>
          </td>
        </tr>
      `).join("");
    }
  }
}

function renderInspectorResult(data) {
  const panel = document.getElementById("inspector-result-panel");
  const isDanger = data.is_phishing;
  const badgeClass = isDanger ? "danger" : "safe";
  const statusTitle = isDanger ? "Phishing / Malicious" : "Legitimate / Benign";
  const description = isDanger
    ? "Warning: This URL displays statistical and structural anomalies (such as token manipulation, suspicious keywords, or deceptive subdomains) commonly seen in phishing and scam campaigns."
    : "Verified Safe: Structural properties, entropy distribution, and domain credentials conform to standard legitimate web architecture.";

  let featuresHtml = "";
  if (data.features) {
    for (const [key, val] of Object.entries(data.features)) {
      featuresHtml += `
        <div class="feat-item">
          <span class="feat-name">${key}:</span>
          <span class="feat-val">${val}</span>
        </div>
      `;
    }
  }

  if (panel) {
    panel.className = "panel";
    panel.innerHTML = `
      <div class="result-card ${badgeClass}">
        <div class="res-top-row">
          <span class="res-title">${statusTitle}</span>
          <span class="res-conf">${data.confidence}% Confidence</span>
        </div>
        <p class="res-msg">${description}</p>
        <div style="font-size: 0.74rem; color: var(--text-muted); margin-bottom: 14px;">
          Evaluated via: <strong>${data.tier}</strong>
        </div>
        <button class="features-toggle-btn" id="feat-toggle-btn">&#9660; View Extracted Feature Metrics</button>
        <div class="features-grid-17" id="features-grid-box">
          ${featuresHtml}
        </div>
      </div>
    `;

    const toggleBtn = document.getElementById("feat-toggle-btn");
    const gridBox = document.getElementById("features-grid-box");
    if (toggleBtn && gridBox) {
      toggleBtn.addEventListener("click", () => {
        if (gridBox.style.display === "none") {
          gridBox.style.display = "grid";
          toggleBtn.innerHTML = "&#9660; Hide Extracted Feature Metrics";
        } else {
          gridBox.style.display = "none";
          toggleBtn.innerHTML = "&#9654; View Extracted Feature Metrics";
        }
      });
    }
  }
}

function initializeCharts() {
  Chart.defaults.color = "#8b9bb4";
  Chart.defaults.font.family = "Inter, sans-serif";

  // 1. Dashboard Threat Donut
  const ctxDonut = document.getElementById("threatOverviewDonut")?.getContext("2d");
  if (ctxDonut) {
    threatDonutChart = new Chart(ctxDonut, {
      type: "doughnut",
      data: {
        datasets: [{
          data: [3, 2],
          backgroundColor: ["#06b6d4", "#ef4444"],
          borderWidth: 0,
          hoverOffset: 6
        }]
      },
      options: {
        cutout: "76%",
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } }
      }
    });
  }

  // 2. Attack Vector Radar Chart
  const ctxRadar = document.getElementById("attackVectorRadar")?.getContext("2d");
  if (ctxRadar) {
    attackRadarChart = new Chart(ctxRadar, {
      type: "radar",
      data: {
        labels: ["Keywords", "Subdomains", "Hyphens", "IP Targeting", "Special Chars", "Length"],
        datasets: [{
          label: "Threat Density",
          data: [65, 45, 55, 30, 40, 70],
          backgroundColor: "rgba(6, 182, 212, 0.25)",
          borderColor: "#06b6d4",
          borderWidth: 2,
          pointBackgroundColor: "#06b6d4",
          pointRadius: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          r: {
            angleLines: { color: "rgba(255, 255, 255, 0.08)" },
            grid: { color: "rgba(255, 255, 255, 0.08)" },
            pointLabels: { font: { size: 10 }, color: "#8b9bb4" },
            ticks: { display: false, max: 100, min: 0 }
          }
        },
        plugins: { legend: { display: false } }
      }
    });
  }

  // 3. Analytics Scan Results Trend
  const ctxTrend = document.getElementById("scanResultsTrendChart")?.getContext("2d");
  if (ctxTrend) {
    trendLineChart = new Chart(ctxTrend, {
      type: "line",
      data: {
        labels: ["Scan #1", "Scan #2", "Scan #3", "Scan #4", "Scan #5"],
        datasets: [
          { label: "Legitimate", data: [1, 2, 3, 3, 3], borderColor: "#06b6d4", backgroundColor: "rgba(6, 182, 212, 0.15)", borderWidth: 2, tension: 0.4, fill: true },
          { label: "Malicious", data: [0, 0, 0, 1, 2], borderColor: "#ef4444", backgroundColor: "rgba(239, 68, 68, 0.15)", borderWidth: 2, tension: 0.4, fill: true }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false } },
          y: { grid: { color: "rgba(255,255,255,0.05)" } }
        }
      }
    });
  }

  // 4. Analytics Top Threat Donut
  const ctxThreatDonut = document.getElementById("topThreatDonutChart")?.getContext("2d");
  if (ctxThreatDonut) {
    topThreatDonut = new Chart(ctxThreatDonut, {
      type: "doughnut",
      data: {
        datasets: [{
          data: [28, 18, 15, 12, 10, 17],
          backgroundColor: ["#06b6d4", "#3b82f6", "#ef4444", "#f59e0b", "#8b5cf6", "#64748b"],
          borderWidth: 0
        }]
      },
      options: {
        cutout: "75%",
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } }
      }
    });
  }

  // 5. Model Evaluation Bar Chart
  const ctxBar = document.getElementById("modelPerfBarChart")?.getContext("2d");
  if (ctxBar) {
    modelBarChart = new Chart(ctxBar, {
      type: "bar",
      data: {
        labels: ["Legitimate (0)", "Phishing (1)"],
        datasets: [
          { label: "Precision", data: [0.95, 0.94], backgroundColor: "#3b82f6", borderRadius: 4 },
          { label: "Recall", data: [0.94, 0.95], backgroundColor: "#06b6d4", borderRadius: 4 },
          { label: "F1-Score", data: [0.94, 0.94], backgroundColor: "#8b5cf6", borderRadius: 4 }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false } },
          y: { min: 0, max: 1.0, grid: { color: "rgba(255,255,255,0.05)" } }
        }
      }
    });
  }
}

async function checkBackendHealth() {
  const start = performance.now();
  const statusEl = document.getElementById("backend-status-text");
  const pingEl = document.getElementById("backend-ping");

  try {
    const res = await fetch(`${API_BASE}/`);
    const elapsed = Math.round(performance.now() - start);
    if (res.ok) {
      if (statusEl) statusEl.textContent = "Backend API: Running";
      if (pingEl) pingEl.textContent = `Response Time: ${elapsed}ms`;
    }
  } catch {
    if (statusEl) {
      statusEl.textContent = "Backend: Offline";
      statusEl.style.color = "var(--accent-red)";
    }
    if (pingEl) pingEl.textContent = "Please start Uvicorn";
  }
}