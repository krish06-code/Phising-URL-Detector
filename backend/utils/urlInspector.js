/**
 * urlInspector.js
 * ===============
 * Analyzes the structural characteristics of a URL to provide
 * factual, explainable signals (positive and negative).
 *
 * Used in Phase 2 for explainable security warnings so users understand
 * exactly what characteristics contributed to a safety or phishing assessment.
 *
 * NOTE: Never fabricates signals. Every signal is derived directly from
 * inspecting the URL string and parsed components.
 */

const { parseDomain, isIpAddress } = require("./domainParser");

/**
 * Inspects a URL and returns factual structural characteristics.
 *
 * @param {string} rawUrl - Full URL to inspect
 * @param {object} [mlFeatures] - Optional features returned from the Python ML extractor
 * @returns {object} Structural breakdown with positive and suspicious signals
 */
function inspectUrlCharacteristics(rawUrl, mlFeatures = null) {
  const parsed = parseDomain(rawUrl);

  const suspiciousSignals = [];
  const safetySignals = [];

  if (!parsed || !parsed.isValid) {
    return {
      protocol: "unknown",
      isHttps: false,
      isIp: false,
      subdomainCount: 0,
      hasObfuscation: false,
      suspiciousSignals: ["Malformed or unparseable URL structure"],
      safetySignals: [],
    };
  }

  // 1. Protocol / Transport Security
  const isHttps = parsed.protocol === "https:";
  if (isHttps) {
    safetySignals.push({
      id: "https_secure",
      label: "HTTPS Encryption",
      description: "Uses secure encrypted transport (HTTPS).",
      severity: "positive",
    });
  } else {
    suspiciousSignals.push({
      id: "no_https",
      label: "Insecure Protocol (HTTP)",
      description: "Website uses unencrypted HTTP; sensitive data could be intercepted.",
      severity: "warning",
    });
  }

  // 2. IP Address as Hostname
  if (parsed.isIp) {
    suspiciousSignals.push({
      id: "ip_hostname",
      label: "IP Address Hostname",
      description: `Uses a raw IP address (${parsed.hostname}) instead of a domain name, a common phishing evasion technique.`,
      severity: "high",
    });
  } else {
    safetySignals.push({
      id: "registered_domain",
      label: "Named Registered Domain",
      description: `Routes through standard domain name system (${parsed.registeredDomain}).`,
      severity: "positive",
    });
  }

  // 3. Subdomain Depth
  const subparts = parsed.subdomain ? parsed.subdomain.split(".") : [];
  const subdomainCount = subparts.length;

  if (subdomainCount >= 3) {
    suspiciousSignals.push({
      id: "excessive_subdomains",
      label: "Excessive Subdomains",
      description: `Domain has ${subdomainCount} subdomains (${parsed.subdomain}), often used to bury fraudulent hostnames.`,
      severity: "medium",
    });
  } else if (subdomainCount === 0 || (subdomainCount === 1 && subparts[0] === "www")) {
    safetySignals.push({
      id: "clean_subdomain",
      label: "Clean Subdomain Structure",
      description: "Direct domain without excessive or suspicious subdomain nesting.",
      severity: "positive",
    });
  }

  // 4. URL Length
  const urlLen = rawUrl.length;
  if (urlLen > 100) {
    suspiciousSignals.push({
      id: "length_long",
      label: "Unusually Long URL",
      description: `URL contains ${urlLen} characters; long URLs are often used to hide the true destination.`,
      severity: "low",
    });
  } else if (urlLen < 50) {
    safetySignals.push({
      id: "length_normal",
      label: "Concise URL Length",
      description: `Standard, readable URL length (${urlLen} characters).`,
      severity: "positive",
    });
  }

  // 5. Hex/Percent-Encoded Obfuscation
  const percentMatches = rawUrl.match(/%[0-9A-Fa-f]{2}/g) || [];
  if (percentMatches.length > 2) {
    suspiciousSignals.push({
      id: "hex_obfuscation",
      label: "Encoded Obfuscation Detected",
      description: `Contains ${percentMatches.length} encoded characters (%xx) which may mask destination terms.`,
      severity: "medium",
    });
  }

  // 6. Digit Density in Domain Name
  const digitsInMain = (parsed.mainDomain.match(/\d/g) || []).length;
  const mainLen = parsed.mainDomain.length;
  const digitRatio = mainLen > 0 ? digitsInMain / mainLen : 0;

  if (!parsed.isIp && digitRatio > 0.25) {
    suspiciousSignals.push({
      id: "high_digit_ratio",
      label: "High Number of Digits in Domain",
      description: `${Math.round(digitRatio * 100)}% of the domain name consists of numbers, characteristic of algorithmic or generated domains.`,
      severity: "medium",
    });
  }

  // 7. Multiple Hyphens in Registered Domain
  const hyphenCount = (parsed.mainDomain.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    suspiciousSignals.push({
      id: "multiple_hyphens",
      label: "Multiple Hyphens in Domain",
      description: `Domain contains ${hyphenCount} hyphens (${parsed.mainDomain}), frequently seen in combosquatting and typosquatting.`,
      severity: "medium",
    });
  }

  return {
    protocol: parsed.protocol,
    isHttps,
    isIp: parsed.isIp,
    hostname: parsed.hostname,
    registeredDomain: parsed.registeredDomain,
    subdomain: parsed.subdomain,
    subdomainCount,
    urlLength: urlLen,
    hasObfuscation: percentMatches.length > 0,
    suspiciousSignals,
    safetySignals,
  };
}

module.exports = {
  inspectUrlCharacteristics,
};
