/**
 * explainability.test.js
 * =======================
 * Automated unit tests for:
 * 1. urlInspector.js (URL structural signals, positive & suspicious indicators)
 * 2. explainability.js (Multi-tier explainable security report)
 *
 * Can be run standalone with:
 *   node backend/tests/explainability.test.js
 */

const { inspectUrlCharacteristics } = require("../utils/urlInspector");
const { buildSecurityExplanation } = require("../utils/explainability");
const { brandDetector } = require("../services/brandDetector");

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${err.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || "Assertion failed");
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

console.log("\n" + "=".repeat(60));
console.log("PhishGuard Phase 2: Explainable Security Warnings Tests");
console.log("=".repeat(60));

// -------------------------------------------------------------
// Suite 1: URL Structural Inspector Tests
// -------------------------------------------------------------
console.log("\n[1. URL Characteristics Inspector Tests]");

test("Detects HTTPS encryption as safety signal", () => {
  const c = inspectUrlCharacteristics("https://example.com");
  assertEqual(c.isHttps, true, "isHttps");
  const hasHttpsSignal = c.safetySignals.some((s) => s.id === "https_secure");
  assert(hasHttpsSignal, "Should include https_secure safety signal");
});

test("Detects HTTP insecure protocol as suspicious signal", () => {
  const c = inspectUrlCharacteristics("http://example.com");
  assertEqual(c.isHttps, false, "isHttps");
  const hasInsecureSignal = c.suspiciousSignals.some((s) => s.id === "no_https");
  assert(hasInsecureSignal, "Should include no_https suspicious signal");
});

test("Detects raw IP address hostname", () => {
  const c = inspectUrlCharacteristics("http://192.168.1.1/login");
  assertEqual(c.isIp, true, "isIp");
  const hasIpSignal = c.suspiciousSignals.some((s) => s.id === "ip_hostname");
  assert(hasIpSignal, "Should include ip_hostname suspicious signal");
});

test("Detects excessive subdomains", () => {
  const c = inspectUrlCharacteristics("https://a.b.c.d.example.com");
  assert(c.subdomainCount >= 3, "subdomainCount should be >= 3");
  const hasSubdomainSignal = c.suspiciousSignals.some((s) => s.id === "excessive_subdomains");
  assert(hasSubdomainSignal, "Should flag excessive subdomains");
});

test("Detects percent-encoded hex obfuscation", () => {
  const c = inspectUrlCharacteristics("https://example.com/%20%2f%2e%61");
  assertEqual(c.hasObfuscation, true, "hasObfuscation");
  const hasHexSignal = c.suspiciousSignals.some((s) => s.id === "hex_obfuscation");
  assert(hasHexSignal, "Should flag hex obfuscation");
});

test("Detects multiple hyphens in domain name", () => {
  const c = inspectUrlCharacteristics("https://secure-login-account-update.com");
  const hasHyphenSignal = c.suspiciousSignals.some((s) => s.id === "multiple_hyphens");
  assert(hasHyphenSignal, "Should flag multiple hyphens in domain");
});

// -------------------------------------------------------------
// Suite 2: Multi-Tier Explainability Builder Tests
// -------------------------------------------------------------
console.log("\n[2. Multi-Tier Explainability Builder Tests]");

test("Generates 3-tier explanation for brand impersonation URL", () => {
  const url = "https://amazon.com.example.net/login";
  const brandAnalysis = brandDetector.analyze(url);
  const mlResult = {
    prediction: "phishing",
    risk_score: 0.25,
    model_version: "3.0",
    message: "ML model flagged suspicious structure",
  };

  const exp = buildSecurityExplanation({
    url,
    mlResult,
    brandAnalysis,
    riskLevel: "high",
  });

  // Plain-English Summary
  assert(exp.summary.length > 20, "Should include a non-empty summary");
  assert(exp.summary.includes("Amazon"), "Summary should explain Amazon impersonation");
  assert(exp.summary.includes("example.net"), "Summary should explain actual registered domain");

  // Tier 1: Machine Learning
  assertEqual(exp.tiers.machine_learning.classification, "phishing", "ML classification");
  assert(exp.tiers.machine_learning.structural_signals.length > 0, "ML structural signals present");

  // Tier 2: Heuristics
  assertEqual(exp.tiers.heuristics.brand_impersonation_detected, true, "brand_impersonation_detected");
  assertEqual(exp.tiers.heuristics.brand_name, "Amazon", "brand_name");
  assertEqual(exp.tiers.heuristics.threat_type, "misleading_subdomain", "threat_type");
  assertEqual(exp.tiers.heuristics.actual_registered_domain, "example.net", "actual_registered_domain");

  // Tier 3: Threat Intelligence
  assertEqual(exp.tiers.threat_intelligence.status, "unmatched", "Threat intel status");
  assertEqual(exp.tiers.threat_intelligence.matched, false, "Threat intel matched");
  assert(exp.tiers.threat_intelligence.detail.includes("ML"), "Threat intel clarifies local ML inspection");
});

test("Generates explanation for verified official brand domain", () => {
  const url = "https://www.google.com/search?q=test";
  const brandAnalysis = brandDetector.analyze(url);
  const mlResult = {
    prediction: "legitimate",
    risk_score: 0.98,
    model_version: "3.0",
    message: "Legitimate website structure",
  };

  const exp = buildSecurityExplanation({
    url,
    mlResult,
    brandAnalysis,
    riskLevel: "low",
  });

  assert(exp.summary.includes("Verified official domain"), "Summary states verified official domain");
  assertEqual(exp.tiers.heuristics.is_official_brand_domain, true, "is_official_brand_domain");
  assertEqual(exp.tiers.heuristics.brand_name, "Google", "brand_name");
  assertEqual(exp.tiers.machine_learning.classification, "legitimate", "ML classification");
});

test("Generates explanation for neutral legitimate website", () => {
  const url = "https://en.wikipedia.org/wiki/Main_Page";
  const brandAnalysis = brandDetector.analyze(url);
  const mlResult = {
    prediction: "legitimate",
    risk_score: 0.95,
    model_version: "3.0",
    message: "Legitimate structure",
  };

  const exp = buildSecurityExplanation({
    url,
    mlResult,
    brandAnalysis,
    riskLevel: "low",
  });

  assertEqual(exp.tiers.heuristics.brand_impersonation_detected, false, "No impersonation");
  assertEqual(exp.tiers.heuristics.is_official_brand_domain, false, "Not a protected brand");
  assert(exp.summary.includes("legitimate"), "Summary explains legitimate status");
  assertEqual(exp.url_characteristics.registered_domain, "wikipedia.org", "registered_domain");
});

test("Generates explanation for ML-flagged phishing without brand impersonation", () => {
  const url = "http://192.168.1.1/admin-login";
  const brandAnalysis = brandDetector.analyze(url);
  const mlResult = {
    prediction: "phishing",
    risk_score: 0.15,
    model_version: "3.0",
    message: "High risk characteristics",
  };

  const exp = buildSecurityExplanation({
    url,
    mlResult,
    brandAnalysis,
    riskLevel: "high",
  });

  assertEqual(exp.tiers.heuristics.brand_impersonation_detected, false, "No brand impersonation");
  assertEqual(exp.tiers.machine_learning.classification, "phishing", "ML prediction");
  const hasIpSuspicious = exp.tiers.machine_learning.structural_signals.some(
    (s) => s.label.includes("IP")
  );
  assert(hasIpSuspicious, "Signals should include IP hostname");
});

// -------------------------------------------------------------
// Summary
// -------------------------------------------------------------
console.log("\n" + "=".repeat(60));
console.log(`Explainability Test Results: ${passed} passed, ${failed} failed`);
console.log("=".repeat(60) + "\n");

if (failed > 0) process.exit(1);
else process.exit(0);
