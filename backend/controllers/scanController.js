/**
 * scanController.js
 * =================
 * Request handlers for the /api/scan and /api/health routes.
 *
 * Controllers should be thin:
 * - Validate the request
 * - Call the appropriate service
 * - Format and return the response
 * - Let the error handler middleware deal with thrown errors
 */

const mlService = require("../services/mlService");
const { validateScanRequestBody } = require("../utils/validators");
const { brandDetector } = require("../services/brandDetector");
const { buildSecurityExplanation } = require("../utils/explainability");

/**
 * GET /api/health
 *
 * Returns the health status of both the Node.js server and the ML service.
 * The Chrome extension uses this to show a "service offline" message if needed.
 */
async function healthCheck(req, res) {
  const mlHealth = await mlService.checkHealth();

  const overallStatus = mlHealth.reachable && mlHealth.modelLoaded
    ? "ready"
    : mlHealth.reachable
      ? "model_not_loaded"
      : "ml_service_unavailable";

  res.json({
    status: overallStatus,
    services: {
      backend: { status: "ok", version: "1.0.0" },
      mlService: {
        reachable: mlHealth.reachable,
        modelLoaded: mlHealth.modelLoaded,
        modelVersion: mlHealth.modelVersion,
      },
    },
  });
}

/**
 * POST /api/scan
 *
 * Accepts a URL from the Chrome extension, validates it, evaluates
 * brand impersonation, forwards it to the ML service, and returns
 * the combined prediction result.
 *
 * Request body: { "url": "https://example.com" }
 */
/**
 * normalizeUrlForModel(url)
 * -------------------------
 * Extracts just the origin (scheme + hostname) from a URL before
 * sending it to the ML model.
 */
function normalizeUrlForModel(url) {
  try {
    const parsed = new URL(url);

    // Build origin-only URL (no path, no query, no fragment)
    let hostname = parsed.hostname;

    // Add www. prefix for bare domains (e.g., github.com → www.github.com)
    const dotCount = (hostname.match(/\./g) || []).length;
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
    if (dotCount === 1 && !isIp && parsed.protocol === "https:") {
      hostname = "www." + hostname;
    }

    return parsed.protocol + "//" + hostname;
  } catch {
    // If URL parsing fails, return as-is
    return url;
  }
}

async function scanUrl(req, res, next) {
  // Step 1: Validate the request body
  const validation = validateScanRequestBody(req.body);
  if (!validation.valid) {
    return res.status(400).json({
      success: false,
      error: "invalid_request",
      message: validation.reason,
    });
  }

  const originalUrl = req.body.url.trim();

  // Step 1b: Evaluate Brand Impersonation (Phase 1)
  // Analyzes the full URL for typosquatting, misleading subdomains, homoglyphs, etc.
  const brandAnalysis = brandDetector.analyze(originalUrl);

  // Step 1c: Normalize — strip query params and fragments for the ML model
  const urlForModel = normalizeUrlForModel(originalUrl);

  try {
    // Step 2: Forward normalized URL to ML service and get prediction
    const mlResult = await mlService.getPrediction(urlForModel);

    // Step 3: Combine ML predictions with heuristic Brand Impersonation evidence
    // We do NOT automatically label solely on brand resemblance; we combine
    // the evidence with the ML prediction to produce an explainable composite verdict.
    let riskScore = mlResult.risk_score;
    let prediction = mlResult.prediction;
    let riskLevel;
    let message = mlResult.message;

    if (brandAnalysis.isImpersonation) {
      // Impersonation detected: combine evidence
      // Reduce safety score proportionally based on brand impersonation confidence
      const penalty = brandAnalysis.confidence === "high" ? 0.35 : 0.2;
      riskScore = Math.max(0.05, Math.min(1.0, +(riskScore - penalty).toFixed(4)));

      // If confidence is high or ML already had doubts, classify as phishing
      if (brandAnalysis.confidence === "high" || mlResult.risk_score < 0.6) {
        prediction = "phishing";
        riskLevel = "high";
      } else {
        riskLevel = "medium";
      }

      // Compose a clear explanation detailing the brand impersonation
      message = `${brandAnalysis.warning} ${mlResult.message}`;
    } else {
      // No impersonation detected: standard ML-driven risk thresholds
      if (riskScore < 0.4) {
        riskLevel = "high";
      } else if (riskScore < 0.65) {
        riskLevel = "medium";
      } else {
        riskLevel = "low";
      }

      if (brandAnalysis.isOfficial) {
        message = `Verified official domain of ${brandAnalysis.brand}. ${mlResult.message}`;
      }
    }

    // Step 3b: Build Explainable Security Breakdown (Phase 2)
    // Distinguishes ML predictions, heuristic indicators, and threat intelligence
    const explanation = buildSecurityExplanation({
      url: originalUrl,
      mlResult,
      brandAnalysis,
      riskLevel,
    });

    // Step 4: Return the result with full transparency
    return res.json({
      success: true,
      prediction,
      risk_score: riskScore,
      risk_level: riskLevel,
      message: explanation.summary || message,
      model_version: mlResult.model_version,
      analyzed_url: urlForModel,
      scanned_at: new Date().toISOString(),
      brand_analysis: {
        is_impersonation: brandAnalysis.isImpersonation,
        is_official: brandAnalysis.isOfficial,
        brand: brandAnalysis.brand,
        threat_type: brandAnalysis.threatType,
        confidence: brandAnalysis.confidence,
        reasons: brandAnalysis.reasons,
        warning: brandAnalysis.warning,
        official_domains: brandAnalysis.officialDomains,
        details: brandAnalysis.details,
      },
      evidence: {
        ml_prediction: mlResult.prediction,
        ml_risk_score: mlResult.risk_score,
        brand_impersonation: brandAnalysis.isImpersonation ? brandAnalysis.threatType : "none",
      },
      explanation,
    });

  } catch (err) {
    // Pass to the centralized error handler middleware
    return next(err);
  }
}

module.exports = { healthCheck, scanUrl };

