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
 * Accepts a URL from the Chrome extension, validates it, forwards it to the
 * ML service, and returns the prediction result.
 *
 * Request body: { "url": "https://example.com" }
 *
 * Response:
 * {
 *   "success": true,
 *   "prediction": "phishing" | "legitimate",
 *   "risk_score": 0.0–1.0,
 *   "risk_level": "high" | "medium" | "low",
 *   "message": "Human-readable explanation",
 *   "model_version": "1.0",
 *   "scanned_at": "ISO timestamp"
 * }
 */
/**
 * normalizeUrlForModel(url)
 * -------------------------
 * Extracts just the origin (scheme + hostname) from a URL before
 * sending it to the ML model.
 *
 * Why origin-only (not path or query string)?
 *
 * The PhiUSIIL training dataset contains base-domain URLs like:
 *   https://www.google.com   (legitimate)
 *   http://evil-tracking.xyz (phishing)
 *
 * Real browser URLs often have paths and query strings that look
 * suspicious even for legitimate sites:
 *   /dp/B08J5F3G18          → Amazon product ID (looks random)
 *   /c/abc123-def456        → ChatGPT conversation ID (looks random)
 *   /watch?v=dQw4w9WgXcQ   → YouTube video ID
 *   ?sca_esv=80abbfb07...   → Google tracking params (many = and &)
 *
 * All phishing detection value comes from the DOMAIN:
 *   - Fake TLDs (.tk, .gq, .ru)
 *   - Hyphenated brand names (paypal-security-update.evil.com)
 *   - IP addresses instead of domains (192.168.1.1)
 *   - Excessive subdomains
 *   - No HTTPS
 *
 * Examples:
 *   IN:  https://www.google.com/search?q=hello&sca_esv=abc&rlz=...
 *   OUT: https://www.google.com
 *
 *   IN:  https://chat.openai.com/c/abc123-def456?model=gpt-4
 *   OUT: https://chat.openai.com
 *
 *   IN:  http://paypal-security-update.evil.com/verify?token=x
 *   OUT: http://paypal-security-update.evil.com   (still flagged!)
 */
function normalizeUrlForModel(url) {
  try {
    const parsed = new URL(url);

    // Build origin-only URL (no path, no query, no fragment)
    let hostname = parsed.hostname;

    // Add www. prefix for bare domains (e.g., github.com → www.github.com)
    // The model was trained on www.site.com patterns. Without www., the domain
    // has NoOfSubDomain=0 and a very short URLLength, which the model has
    // learned to associate with phishing (very short, no subdomain structure).
    //
    // We ONLY add www. when:
    //   1. There is exactly one dot in the hostname (bare domain like github.com)
    //   2. It's not an IP address
    //   3. It's HTTPS (don't add www. to http:// suspicious domains)
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

  // Step 1b: Normalize — strip query params and fragments
  // so complex legitimate URLs (Google Search, etc.) aren't falsely flagged
  const urlForModel = normalizeUrlForModel(originalUrl);

  try {
    // Step 2: Forward normalized URL to ML service and get prediction
    const mlResult = await mlService.getPrediction(urlForModel);

    // Step 3: Convert risk_score (0=phishing, 1=legitimate) to a risk level
    // This makes it easier for the extension to choose what color/icon to show
    let riskLevel;
    if (mlResult.risk_score < 0.4) {
      riskLevel = "high";    // likely phishing
    } else if (mlResult.risk_score < 0.65) {
      riskLevel = "medium";  // uncertain
    } else {
      riskLevel = "low";     // likely legitimate
    }

    // Step 4: Return the result
    return res.json({
      success: true,
      prediction: mlResult.prediction,
      risk_score: mlResult.risk_score,
      risk_level: riskLevel,
      message: mlResult.message,
      model_version: mlResult.model_version,
      analyzed_url: urlForModel,    // what the model actually saw (no query params)
      scanned_at: new Date().toISOString(),
    });

  } catch (err) {
    // Pass to the centralized error handler middleware
    return next(err);
  }
}

module.exports = { healthCheck, scanUrl };
