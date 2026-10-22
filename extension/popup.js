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
  // Brand Impersonation UI Elements (Phase 1)
  phishingBrandCard:     document.getElementById("phishingBrandCard"),
  phishingBrandTitle:    document.getElementById("phishingBrandTitle"),
  phishingBrandDesc:     document.getElementById("phishingBrandDesc"),
  phishingBrandReasons:  document.getElementById("phishingBrandReasons"),
  phishingBrandOfficial: document.getElementById("phishingBrandOfficial"),
  uncertainBrandCard:     document.getElementById("uncertainBrandCard"),
  uncertainBrandTitle:    document.getElementById("uncertainBrandTitle"),
  uncertainBrandDesc:     document.getElementById("uncertainBrandDesc"),
  uncertainBrandReasons:  document.getElementById("uncertainBrandReasons"),
  uncertainBrandOfficial: document.getElementById("uncertainBrandOfficial"),
  legitBrandCard:         document.getElementById("legitBrandCard"),
  legitBrandBadge:        document.getElementById("legitBrandBadge"),
  // Explainability Elements (Phase 2)
  explainabilityContainer:   document.getElementById("explainabilityContainer"),
  breakdownToggleBtn:        document.getElementById("breakdownToggleBtn"),
  toggleArrow:               document.getElementById("toggleArrow"),
  breakdownContent:          document.getElementById("breakdownContent"),
  explanationSummaryText:    document.getElementById("explanationSummaryText"),
  tierMlTitle:               document.getElementById("tierMlTitle"),
  tierMlVerdict:             document.getElementById("tierMlVerdict"),
  tierMlSignalsList:         document.getElementById("tierMlSignalsList"),
  tierHeuristicTitle:        document.getElementById("tierHeuristicTitle"),
  tierRegisteredDomain:      document.getElementById("tierRegisteredDomain"),
  tierHeuristicSignalsList:  document.getElementById("tierHeuristicSignalsList"),
  tierThreatIntelStatus:     document.getElementById("tierThreatIntelStatus"),
  tierThreatIntelDesc:       document.getElementById("tierThreatIntelDesc"),
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

  // Hide explainability container if state is idle, scanning, error, or unsupported
  if (stateEl === el.stateIdle || stateEl === el.stateScanning || stateEl === el.stateError || stateEl === el.stateUnsupported) {
    if (el.explainabilityContainer) el.explainabilityContainer.classList.add("hidden");
  }
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

/**
 * Renders a brand impersonation alert card into the specified DOM elements.
 */
function renderBrandCard(cardEl, titleEl, descEl, reasonsEl, officialEl, brandAnalysis) {
  if (!cardEl || !brandAnalysis || !brandAnalysis.is_impersonation) {
    if (cardEl) cardEl.classList.add("hidden");
    return;
  }

  const brandName = brandAnalysis.brand || "Protected Brand";
  const threatTypeLabels = {
    misleading_subdomain: "Misleading Subdomain",
    typosquatting: "Typosquatting Mimic",
    combosquatting: "Combosquatting Pattern",
    homograph: "IDN Homograph Look-alike",
  };
  const threatLabel = threatTypeLabels[brandAnalysis.threat_type] || "Brand Impersonation";

  titleEl.textContent = `⚠️ Resembles ${brandName} (${threatLabel})`;
  descEl.textContent = brandAnalysis.warning || `This domain appears to imitate ${brandName}.`;

  reasonsEl.innerHTML = "";
  if (Array.isArray(brandAnalysis.reasons) && brandAnalysis.reasons.length > 0) {
    brandAnalysis.reasons.forEach((reason) => {
      const li = document.createElement("li");
      li.textContent = reason;
      reasonsEl.appendChild(li);
    });
  }

  if (Array.isArray(brandAnalysis.official_domains) && brandAnalysis.official_domains.length > 0) {
    const topDomains = brandAnalysis.official_domains.slice(0, 3).join(", ");
    officialEl.innerHTML = `Official domain(s): <strong>${topDomains}</strong>`;
    officialEl.classList.remove("hidden");
  } else {
    officialEl.classList.add("hidden");
  }

  cardEl.classList.remove("hidden");
}

// ------------------------------------------------------------------
// Render result
// ------------------------------------------------------------------
function renderResult(result) {
  const { prediction, risk_score, risk_level, message, model_version, scanned_at, brand_analysis } = result;
  el.scanMeta.classList.remove("hidden");
  el.scanTime.textContent = scanned_at ? "Scanned: " + formatTime(scanned_at) : "";
  el.modelVersion.textContent = model_version ? "Model v" + model_version : "";

  // Reset brand cards
  if (el.phishingBrandCard) el.phishingBrandCard.classList.add("hidden");
  if (el.uncertainBrandCard) el.uncertainBrandCard.classList.add("hidden");
  if (el.legitBrandCard) el.legitBrandCard.classList.add("hidden");

  if (prediction === "phishing" || risk_level === "high") {
    el.phishingMessage.textContent = message || "This URL shows characteristics of a phishing site.";
    setRiskMeter(el.riskBar, el.riskScoreDisplay, risk_score, "phishing");
    renderBrandCard(
      el.phishingBrandCard,
      el.phishingBrandTitle,
      el.phishingBrandDesc,
      el.phishingBrandReasons,
      el.phishingBrandOfficial,
      brand_analysis
    );
    showState(el.statePhishing);
  } else if (risk_level === "medium") {
    el.uncertainMessage.textContent = message || "This URL has some unusual characteristics. Proceed with caution.";
    setRiskMeter(el.riskBarUncertain, el.riskScoreDisplayUncertain, risk_score, "uncertain");
    renderBrandCard(
      el.uncertainBrandCard,
      el.uncertainBrandTitle,
      el.uncertainBrandDesc,
      el.uncertainBrandReasons,
      el.uncertainBrandOfficial,
      brand_analysis
    );
    showState(el.stateUncertain);
  } else {
    el.legitMessage.textContent = message || "This URL appears to have the structure of a legitimate site.";
    setRiskMeter(el.riskBarLegit, el.riskScoreDisplayLegit, risk_score, "legit");
    if (brand_analysis && brand_analysis.is_official) {
      if (el.legitBrandCard && el.legitBrandBadge) {
        el.legitBrandBadge.textContent = `✓ Verified ${brand_analysis.brand} Domain`;
        el.legitBrandCard.classList.remove("hidden");
      }
    }
    showState(el.stateLegit);
  }

  // Render 3-Tier Explainable Security Breakdown (Phase 2)
  renderExplainability(result);
}

/**
 * Renders the 3-tier explainable security breakdown (Phase 2).
 */
function renderExplainability(result) {
  if (!el.explainabilityContainer) return;

  const exp = result.explanation;
  const brand = result.brand_analysis;

  // 1. Plain-English Summary
  const summary = exp?.summary || result.message || "Analysis complete.";
  if (el.explanationSummaryText) {
    el.explanationSummaryText.textContent = summary;
  }

  // 2. Tier 1: Machine Learning
  const ml = exp?.tiers?.machine_learning;
  const mlClassification = ml?.classification || result.prediction || "unknown";
  const confidenceStr = ml?.confidence_score || `${Math.round((result.risk_score || 0.5) * 100)}% confidence`;
  if (el.tierMlVerdict) {
    el.tierMlVerdict.textContent = `${confidenceStr} (${mlClassification})`;
  }
  if (el.tierMlTitle) {
    el.tierMlTitle.textContent = result.model_version ? `Model v${result.model_version}` : "Random Forest / XGBoost";
  }

  if (el.tierMlSignalsList) {
    el.tierMlSignalsList.innerHTML = "";
    const signals = ml?.structural_signals || [];
    if (signals.length > 0) {
      signals.forEach((s) => {
        const li = document.createElement("li");
        li.className = s.type === "suspicious" ? "suspicious" : "safe";
        li.textContent = `${s.label}: ${s.detail}`;
        el.tierMlSignalsList.appendChild(li);
      });
    } else {
      const li = document.createElement("li");
      li.className = "safe";
      li.textContent = "Standard alphanumeric structure and expected URL length.";
      el.tierMlSignalsList.appendChild(li);
    }
  }

  // 3. Tier 2: Heuristic & Brand Indicators
  const heuristics = exp?.tiers?.heuristics;
  const regDomain = heuristics?.actual_registered_domain || exp?.url_characteristics?.registered_domain || extractDomain(result.analyzed_url || "");
  if (el.tierRegisteredDomain) {
    el.tierRegisteredDomain.textContent = regDomain || "Unknown";
  }

  if (el.tierHeuristicSignalsList) {
    el.tierHeuristicSignalsList.innerHTML = "";
    if (brand?.is_impersonation) {
      if (el.tierHeuristicTitle) el.tierHeuristicTitle.textContent = `Impersonating ${brand.brand}`;
      const li = document.createElement("li");
      li.className = "suspicious";
      li.textContent = brand.warning || `Domain mimics protected brand ${brand.brand}.`;
      el.tierHeuristicSignalsList.appendChild(li);

      (brand.reasons || []).forEach((r) => {
        const rLi = document.createElement("li");
        rLi.className = "suspicious";
        rLi.textContent = r;
        el.tierHeuristicSignalsList.appendChild(rLi);
      });
    } else if (brand?.is_official) {
      if (el.tierHeuristicTitle) el.tierHeuristicTitle.textContent = `Verified Official ${brand.brand}`;
      const li = document.createElement("li");
      li.className = "safe";
      li.textContent = `Confirmed official registered property of ${brand.brand}.`;
      el.tierHeuristicSignalsList.appendChild(li);
    } else {
      if (el.tierHeuristicTitle) el.tierHeuristicTitle.textContent = "No Brand Impersonation";
      const li = document.createElement("li");
      li.className = "safe";
      li.textContent = "No brand impersonation, typosquatting, or deceptive subdomains detected.";
      el.tierHeuristicSignalsList.appendChild(li);
    }
  }

  // 4. Tier 3: Threat Intelligence
  const threatIntel = exp?.tiers?.threat_intelligence;
  if (el.tierThreatIntelStatus) {
    el.tierThreatIntelStatus.textContent = threatIntel?.status === "matched" ? "Confirmed Threat Match" : "Local Inspection Only";
  }
  if (el.tierThreatIntelDesc) {
    el.tierThreatIntelDesc.textContent = threatIntel?.detail || "No external threat intelligence match. Scanned via ML model and structural heuristics.";
  }

  // Show container
  el.explainabilityContainer.classList.remove("hidden");
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

  // Attach toggle listener for explainability breakdown (Phase 2)
  if (el.breakdownToggleBtn) {
    el.breakdownToggleBtn.addEventListener("click", function() {
      const isHidden = el.breakdownContent.classList.toggle("hidden");
      el.breakdownToggleBtn.setAttribute("aria-expanded", String(!isHidden));
    });
  }
}

init();
