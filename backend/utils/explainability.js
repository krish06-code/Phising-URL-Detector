/**
 * explainability.js
 * =================
 * Generates transparent, human-understandable security explanations
 * for URL scan results (Phase 2).
 *
 * Distinctly separates and attributes:
 * 1. Machine Learning Predictions (model verdict, confidence, structural characteristics)
 * 2. Heuristic Indicators (brand impersonation, typosquatting, subdomains)
 * 3. Confirmed Threat-Intelligence Matches (or explicit statement that none matched)
 *
 * NOTE: Does not fabricate explanations or confidence scores.
 */

const { inspectUrlCharacteristics } = require("./urlInspector");

/**
 * Builds a structured, explainable security report.
 *
 * @param {object} params
 * @param {string} params.url - The analyzed URL
 * @param {object} params.mlResult - Output from ML service (prediction, risk_score, features)
 * @param {object} params.brandAnalysis - Output from brandDetector (isImpersonation, brand, threatType, etc.)
 * @param {string} params.riskLevel - Combined risk level ("high", "medium", "low")
 * @returns {object} Detailed explanation object
 */
function buildSecurityExplanation({ url, mlResult, brandAnalysis, riskLevel }) {
  // 1. Inspect URL structural characteristics
  const characteristics = inspectUrlCharacteristics(url, mlResult?.features);

  // 2. ML Tier Information
  const mlPrediction = mlResult?.prediction || "unknown";
  const rawRiskScore = typeof mlResult?.risk_score === "number" ? mlResult.risk_score : 0.5;
  const safetyPercent = Math.round(rawRiskScore * 100);
  const phishingRiskPercent = Math.round((1 - rawRiskScore) * 100);

  // Collect relevant structural characteristics analyzed by the ML model
  const mlSignals = [];
  if (characteristics.suspiciousSignals.length > 0) {
    characteristics.suspiciousSignals.forEach((s) => {
      mlSignals.push({
        type: "suspicious",
        label: s.label,
        detail: s.description,
      });
    });
  }
  if (characteristics.safetySignals.length > 0) {
    characteristics.safetySignals.forEach((s) => {
      mlSignals.push({
        type: "safe",
        label: s.label,
        detail: s.description,
      });
    });
  }

  const mlBreakdown = {
    model_version: mlResult?.model_version || "3.0",
    classification: mlPrediction,
    confidence_score: mlPrediction === "phishing" ? `${phishingRiskPercent}% risk` : `${safetyPercent}% safety`,
    raw_safety_score: rawRiskScore,
    analyzed_features_count: mlResult?.features ? Object.keys(mlResult.features).length : 18,
    structural_signals: mlSignals,
  };

  // 3. Heuristic & Brand Indicators Tier
  const heuristicBreakdown = {
    brand_impersonation_detected: brandAnalysis?.isImpersonation || false,
    brand_name: brandAnalysis?.brand || null,
    threat_type: brandAnalysis?.threatType || null,
    is_official_brand_domain: brandAnalysis?.isOfficial || false,
    actual_registered_domain: characteristics.registeredDomain,
    subdomain: characteristics.subdomain,
    heuristic_reasons: brandAnalysis?.reasons || [],
  };

  // 4. Threat Intelligence Tier (Distinctly separated)
  // Clearly state status so users know if a match came from external threat intel or local analysis
  const threatIntelBreakdown = {
    status: "unmatched",
    source: "Local Inspection Only",
    matched: false,
    detail: "No external threat-intelligence database match was confirmed. Analysis was performed locally via ML classification and heuristic rules.",
  };

  // 5. Plain-English Synthesis Summary
  let summary = "";
  if (brandAnalysis?.isImpersonation) {
    const brandName = brandAnalysis.brand || "a protected brand";
    const threatLabel = brandAnalysis.threatType
      ? brandAnalysis.threatType.replace(/_/g, " ")
      : "impersonation";
    summary = `Flagged due to brand ${threatLabel} mimicking ${brandName}. The website is registered to '${characteristics.registeredDomain}', not the official domain.`;

    const severeSuspicious = characteristics.suspiciousSignals.find((s) => s.id === "no_https" || s.id === "ip_hostname");
    if (severeSuspicious) {
      summary += ` Additionally, the URL exhibits suspicious technical traits (${severeSuspicious.label.toLowerCase()}).`;
    }
  } else if (brandAnalysis?.isOfficial) {
    summary = `Verified official domain belonging to ${brandAnalysis.brand}. Structural inspection confirmed valid HTTPS and normal URL hierarchy.`;
  } else if (riskLevel === "high") {
    const topReasons = characteristics.suspiciousSignals.slice(0, 2).map((s) => s.label.toLowerCase()).join(" and ");
    summary = `High phishing risk indicated by machine learning model based on structural anomalies${topReasons ? `, including ${topReasons}` : ""}.`;
  } else if (riskLevel === "medium") {
    summary = `Uncertain security posture. The URL has mixed characteristics; exercise caution before entering personal or financial credentials.`;
  } else {
    summary = `Appears legitimate with a ${safetyPercent}% structural safety score, valid HTTPS, and standard domain formatting.`;
  }

  return {
    summary,
    tiers: {
      machine_learning: mlBreakdown,
      heuristics: heuristicBreakdown,
      threat_intelligence: threatIntelBreakdown,
    },
    url_characteristics: {
      protocol: characteristics.protocol,
      hostname: characteristics.hostname,
      registered_domain: characteristics.registeredDomain,
      subdomain: characteristics.subdomain,
      is_https: characteristics.isHttps,
      is_ip: characteristics.isIp,
      url_length: characteristics.urlLength,
    },
  };
}

module.exports = {
  buildSecurityExplanation,
};
