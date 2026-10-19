/**
 * popup.js
 * ========
 * Controls the PhishGuard popup UI.
 *
 * This script runs each time the user opens the extension popup.
 * It communicates with background.js (the service worker) via
 * chrome.runtime.sendMessage(), because the service worker handles
 * the actual fetch() calls to the backend.
 *
 * UI States:
 *   idle       -> waiting for user to click "Scan"
 *   scanning   -> request in flight
 *   phishing   -> result: phishing detected (risk_score < 0.4)
 *   uncertain  -> result: uncertain       (risk_score 0.4-0.65)
 *   legit      -> result: looks legitimate (risk_score > 0.65)
 *   error      -> backend/ML service unreachable
 *   unsupported-> current tab URL is chrome://, about:, etc.
 */

"use strict";

// ------------------------------------------------------------------
// Element references
// ------------------------------------------------------------------
const el = {
  statusDot: document.getElementById("statusDot"),
  currentUrl: document.getElementById("currentUrl"),
  stateIdle:        document.getElementById("stateIdle"),
  stateScanning:    document.getElementById("stateScanning"),
  statePhishing:    document.getElementById("statePhishing"),
  stateLegit:       document.getElementById("stateLegit"),
  stateUncertain:   document.getElementById("stateUncertain"),
  stateError:       document.getElementById("stateError"),
  stateUnsupported: document.getElementById("stateUnsupported"),
  phishingMessage:           document.getElementById("phishingMessage"),
  legitMessage:              document.getElementById("legitMessage"),
  uncertainMessage:          document.getElementById("uncertainMessage"),
  errorMessage:              document.getElementById("errorMessage"),
  riskBar:                   document.getElementById("riskBar"),
  riskScoreDisplay:          document.getElementById("riskScoreDisplay"),
  riskBarLegit:              document.getElementById("riskBarLegit"),
  riskScoreDisplayLegit:     document.getElementById("riskScoreDisplayLegit"),
  riskBarUncertain:          document.getElementById("riskBarUncertain"),
  riskScoreDisplayUncertain: document.getElementById("riskScoreDisplayUncertain"),
  scanBtn:         document.getElementById("scanBtn"),
  btnText:         document.getElementById("btnText"),
  scanMeta:        document.getElementById("scanMeta"),
  scanTime:        document.getElementById("scanTime"),
  modelVersion:    document.getElementById("modelVersion"),
  historySection:  document.getElementById("historySection"),
  historyList:     document.getElementById("historyList"),
  clearHistoryBtn: document.getElementById("clearHistoryBtn"),
};

const ALL_STATES = [
  el.stateIdle, el.stateScanning, el.statePhishing,
  el.stateLegit, el.stateUncertain, el.stateError, el.stateUnsupported,
];

// ------------------------------------------------------------------
// State management
// ------------------------------------------------------------------
function showState(stateEl) {
  ALL_STATES.forEach((s) => s.classList.add("hidden"));
  stateEl.classList.remove("hidden");
}

function setStatusDot(status) {
  el.statusDot.className = "status-dot";
  if (status === "online")   el.statusDot.classList.add("online");
  if (status === "offline")  el.statusDot.classList.add("offline");
  if (status === "checking") el.statusDot.classList.add("checking");
  const titles = {
    online: "Backend: online", offline: "Backend: offline", checking: "Checking backend...",
  };
  el.statusDot.title = titles[status] || "Unknown";
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------
function isSupportedUrl(url) {
  if (!url) return false;
  return url.startsWith("http://") || url.startsWith("https://");
}

function formatTime(isoString) {
  if (!isoString) return "";
  try {
    const date = new Date(isoString);
    const diffMin = Math.floor((Date.now() - date.getTime()) / 60000);
    if (diffMin < 1)  return "Just now";
    if (diffMin < 60) return diffMin + "m ago";
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch { return ""; }
}

function setRiskMeter(barEl, displayEl, riskScore, type) {
  if (!barEl || !displayEl) return;
  let widthPercent, color;
  if (type === "phishing") {
    widthPercent = Math.round((1 - riskScore) * 100);
    color = "var(--accent-red)";
  } else if (type === "legit") {
    widthPercent = Math.round(riskScore * 100);
    color = "var(--accent-green)";
  } else {
    widthPercent = Math.round(riskScore * 100);
    color = "var(--accent-orange)";
  }
  barEl.style.width = widthPercent + "%";
  barEl.style.background = color;
  const pct = Math.round(riskScore * 100);
  displayEl.textContent = type === "phishing"
    ? "Risk: " + (100 - pct) + "% (score " + riskScore.toFixed(2) + ")"
    : "Score: " + pct + "% (" + riskScore.toFixed(2) + ")";
}

// ------------------------------------------------------------------
// Render result
// ------------------------------------------------------------------
function renderResult(result) {
  const { prediction, risk_score, risk_level, message, model_version, scanned_at } = result;
  el.scanMeta.classList.remove("hidden");
  el.scanTime.textContent = scanned_at ? "Scanned: " + formatTime(scanned_at) : "";
  el.modelVersion.textContent = model_version ? "Model v" + model_version : "";

  if (prediction === "phishing" || risk_level === "high") {
    el.phishingMessage.textContent = message || "This URL shows characteristics of a phishing site.";
    setRiskMeter(el.riskBar, el.riskScoreDisplay, risk_score, "phishing");
    showState(el.statePhishing);
  } else if (risk_level === "medium") {
    el.uncertainMessage.textContent = message || "This URL has some unusual characteristics. Proceed with caution.";
    setRiskMeter(el.riskBarUncertain, el.riskScoreDisplayUncertain, risk_score, "uncertain");
    showState(el.stateUncertain);
  } else {
    el.legitMessage.textContent = message || "This URL appears to have the structure of a legitimate site.";
    setRiskMeter(el.riskBarLegit, el.riskScoreDisplayLegit, risk_score, "legit");
    showState(el.stateLegit);
  }
}

// ------------------------------------------------------------------
// History
// ------------------------------------------------------------------
function renderHistory(history) {
  if (!history || history.length === 0) {
    el.historySection.classList.add("hidden");
    return;
  }
  el.historySection.classList.remove("hidden");
  el.historyList.innerHTML = "";
  history.slice(0, 5).forEach(function(entry) {
    const li = document.createElement("li");
    li.className = "history-item";
    const badgeClass = entry.risk_level === "high" ? "phishing" : entry.risk_level === "medium" ? "medium" : "legitimate";
    const badgeText  = entry.risk_level === "high" ? "Phishing" : entry.risk_level === "medium" ? "Warn" : "Safe";
    li.innerHTML =
      '<span class="history-badge ' + badgeClass + '">' + badgeText + '</span>' +
      '<span class="history-domain" title="' + entry.domain + '">' + entry.domain + '</span>' +
      '<span class="history-time">' + formatTime(entry.scanned_at) + '</span>';
    el.historyList.appendChild(li);
  });
}

async function loadHistory() {
  try {
    const stored = await chrome.storage.local.get("scan_history");
    renderHistory(stored.scan_history || []);
  } catch { /* history is optional */ }
}

el.clearHistoryBtn.addEventListener("click", async function() {
  try {
    await chrome.storage.local.remove("scan_history");
    el.historySection.classList.add("hidden");
    el.historyList.innerHTML = "";
  } catch { /* ignore */ }
});

// ------------------------------------------------------------------
// Health check
// ------------------------------------------------------------------
async function checkHealth() {
  setStatusDot("checking");
  try {
    const response = await new Promise(function(resolve, reject) {
      chrome.runtime.sendMessage({ type: "CHECK_HEALTH" }, function(resp) {
        if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
        else resolve(resp);
      });
    });
    if (response && response.success && response.data && response.data.status === "ready") {
      setStatusDot("online");
    } else {
      setStatusDot("offline");
    }
  } catch { setStatusDot("offline"); }
}

// ------------------------------------------------------------------
// Scan button handler
// ------------------------------------------------------------------
el.scanBtn.addEventListener("click", async function() {
  let tabs;
  try {
    tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch (err) {
    showError("Could not access the current tab.");
    return;
  }

  const url = tabs[0] && tabs[0].url;

  if (!isSupportedUrl(url)) {
    showState(el.stateUnsupported);
    return;
  }

  el.scanBtn.disabled = true;
  el.scanBtn.classList.add("scanning");
  el.btnText.textContent = "Scanning...";
  el.scanMeta.classList.add("hidden");
  showState(el.stateScanning);

  try {
    const response = await new Promise(function(resolve, reject) {
      chrome.runtime.sendMessage({ type: "SCAN_URL", url: url }, function(resp) {
        if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
        else resolve(resp);
      });
    });

    if (!response)          throw new Error("No response from background service worker.");
    if (!response.success)  throw new Error(response.error || "Scan failed.");

    renderResult(response.data);
    loadHistory();

  } catch (err) {
    showError(err.message);
    setStatusDot("offline");
  } finally {
    el.scanBtn.disabled = false;
    el.scanBtn.classList.remove("scanning");
    el.btnText.textContent = "Scan Again";
  }
});

function showError(message) {
  if (message) el.errorMessage.textContent = message;
  showState(el.stateError);
}

// ------------------------------------------------------------------
// Initialization
// ------------------------------------------------------------------
async function init() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = (tabs[0] && tabs[0].url) || "";
    if (!url) {
      el.currentUrl.textContent = "No URL available";
      el.currentUrl.classList.add("unsupported");
    } else if (!isSupportedUrl(url)) {
      el.currentUrl.textContent = url.substring(0, 60) || "(browser page)";
      el.currentUrl.classList.add("unsupported");
      showState(el.stateUnsupported);
      return;
    } else {
      el.currentUrl.textContent = url;
      el.currentUrl.classList.remove("unsupported");
    }
  } catch {
    el.currentUrl.textContent = "Could not read URL";
    el.currentUrl.classList.add("unsupported");
  }

  checkHealth();
  loadHistory();
}

init();
