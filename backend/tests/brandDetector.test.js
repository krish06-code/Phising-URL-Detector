/**
 * brandDetector.test.js
 * =====================
 * Automated unit tests for:
 * 1. domainParser.js (Domain splitting, TLDs, subdomains, punycode, IPs)
 * 2. homoglyphs.js (Unicode confusable mapping, leetspeak, Levenshtein distance)
 * 3. brandDetector.js (Brand impersonation detection)
 *
 * Can be run standalone with:
 *   node backend/tests/brandDetector.test.js
 * (No external services required)
 */

const { parseDomain } = require("../utils/domainParser");
const {
  normalizeHomoglyphs,
  normalizeLeetspeak,
  levenshteinDistance,
} = require("../utils/homoglyphs");
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
console.log("PhishGuard Phase 1: Brand Impersonation Detection Tests");
console.log("=".repeat(60));

// -------------------------------------------------------------
// Suite 1: Domain Parser
// -------------------------------------------------------------
console.log("\n[1. Domain Parser Tests]");

test("Parses standard domain correctly", () => {
  const p = parseDomain("https://www.google.com/search?q=test");
  assert(p !== null, "Parsing returned null");
  assertEqual(p.hostname, "www.google.com", "hostname");
  assertEqual(p.registeredDomain, "google.com", "registeredDomain");
  assertEqual(p.mainDomain, "google", "mainDomain");
  assertEqual(p.subdomain, "www", "subdomain");
  assertEqual(p.tld, "com", "tld");
});

test("Parses multi-part public suffix (.co.uk)", () => {
  const p = parseDomain("https://sub.paypa1.co.uk/verify");
  assert(p !== null, "Parsing returned null");
  assertEqual(p.hostname, "sub.paypa1.co.uk", "hostname");
  assertEqual(p.registeredDomain, "paypa1.co.uk", "registeredDomain");
  assertEqual(p.mainDomain, "paypa1", "mainDomain");
  assertEqual(p.subdomain, "sub", "subdomain");
  assertEqual(p.tld, "co.uk", "tld");
});

test("Distinguishes misleading subdomain from registered domain", () => {
  const p = parseDomain("https://amazon.com.example.net/login");
  assert(p !== null, "Parsing returned null");
  assertEqual(p.hostname, "amazon.com.example.net", "hostname");
  assertEqual(p.registeredDomain, "example.net", "registeredDomain (actual domain)");
  assertEqual(p.subdomain, "amazon.com", "subdomain (misleading brand spoof)");
  assertEqual(p.mainDomain, "example", "mainDomain");
});

test("Handles IP addresses correctly", () => {
  const p = parseDomain("http://192.168.1.100/admin");
  assert(p !== null, "Parsing returned null");
  assert(p.isIp === true, "isIp should be true");
  assertEqual(p.registeredDomain, "192.168.1.100", "registeredDomain for IP");
});

test("Decodes Punycode IDN domains", () => {
  const p = parseDomain("https://xn--gogle-pqa.com/path");
  assert(p !== null, "Parsing returned null");
  assert(p.isPunycode === true, "isPunycode should be true");
  assert(p.unicodeHostname.length > 0, "unicodeHostname should be present");
});

// -------------------------------------------------------------
// Suite 2: Homoglyphs and Leetspeak Utilities
// -------------------------------------------------------------
console.log("\n[2. Homoglyph & Similarity Utility Tests]");

test("Calculates Levenshtein distance accurately", () => {
  assertEqual(levenshteinDistance("amazon", "amazon"), 0, "identical");
  assertEqual(levenshteinDistance("amzon", "amazon"), 1, "deletion");
  assertEqual(levenshteinDistance("gogle", "google"), 1, "deletion");
  assertEqual(levenshteinDistance("paypaal", "paypal"), 1, "insertion");
  assertEqual(levenshteinDistance("kitten", "sitting"), 3, "substitution & insertion");
});

test("Normalizes leetspeak substitutions", () => {
  const variants = normalizeLeetspeak("amaz0n");
  assert(variants.includes("amazon"), "amaz0n should produce amazon");

  const pVariants = normalizeLeetspeak("paypa1");
  assert(pVariants.includes("paypal"), "paypa1 should produce paypal");
});

test("Identifies Cyrillic confusable homoglyphs", () => {
  // Cyrillic small letter o (\u043E)
  const cyrillicGoogle = "g\u043E\u043Egle.com";
  const result = normalizeHomoglyphs(cyrillicGoogle);
  assert(result.hasHomoglyphs === true, "hasHomoglyphs should be true");
  assertEqual(result.normalized, "google.com", "normalized string");
});

// -------------------------------------------------------------
// Suite 3: Official Domains (Should NOT be flagged as impersonation)
// -------------------------------------------------------------
console.log("\n[3. Official Brand Domains Tests]");

test("Recognizes official Google domain", () => {
  const r = brandDetector.analyze("https://www.google.com/search?q=phishguard");
  assertEqual(r.isOfficial, true, "isOfficial");
  assertEqual(r.isImpersonation, false, "isImpersonation");
  assertEqual(r.brand, "Google", "brand");
});

test("Recognizes official Amazon domain with multi-part TLD", () => {
  const r = brandDetector.analyze("https://smile.amazon.co.uk/dp/B08J5F3G18");
  assertEqual(r.isOfficial, true, "isOfficial");
  assertEqual(r.isImpersonation, false, "isImpersonation");
  assertEqual(r.brand, "Amazon", "brand");
});

test("Recognizes official ChatGPT domain", () => {
  const r = brandDetector.analyze("https://chatgpt.com/c/67104b");
  assertEqual(r.isOfficial, true, "isOfficial");
  assertEqual(r.isImpersonation, false, "isImpersonation");
  assert(r.brand.includes("ChatGPT"), "brand includes ChatGPT");
});

test("Recognizes official PayPal domain", () => {
  const r = brandDetector.analyze("https://www.paypal.com/signin");
  assertEqual(r.isOfficial, true, "isOfficial");
  assertEqual(r.isImpersonation, false, "isImpersonation");
  assertEqual(r.brand, "PayPal", "brand");
});

test("Recognizes official Microsoft login domain", () => {
  const r = brandDetector.analyze("https://login.microsoftonline.com");
  assertEqual(r.isOfficial, true, "isOfficial");
  assertEqual(r.isImpersonation, false, "isImpersonation");
  assertEqual(r.brand, "Microsoft", "brand");
});

// -------------------------------------------------------------
// Suite 4: Misleading Subdomains
// -------------------------------------------------------------
console.log("\n[4. Misleading Subdomain Detection Tests]");

test("Detects Amazon misleading subdomain on example.net", () => {
  const r = brandDetector.analyze("https://amazon.com.example.net/login");
  assertEqual(r.isImpersonation, true, "isImpersonation");
  assertEqual(r.threatType, "misleading_subdomain", "threatType");
  assertEqual(r.brand, "Amazon", "brand");
  assert(r.reasons.length > 0, "reasons provided");
  assert(r.warning.includes("Amazon"), "warning mentions Amazon");
});

test("Detects PayPal misleading subdomain", () => {
  const r = brandDetector.analyze("https://paypal.com.verify-user-account.info");
  assertEqual(r.isImpersonation, true, "isImpersonation");
  assertEqual(r.threatType, "misleading_subdomain", "threatType");
  assertEqual(r.brand, "PayPal", "brand");
});

test("Detects ChatGPT misleading subdomain", () => {
  const r = brandDetector.analyze("https://chatgpt.com.login-portal.biz");
  assertEqual(r.isImpersonation, true, "isImpersonation");
  assertEqual(r.threatType, "misleading_subdomain", "threatType");
  assert(r.brand.includes("ChatGPT"), "brand matches ChatGPT");
});

// -------------------------------------------------------------
// Suite 5: Typosquatting (Leetspeak & Character Substitutions)
// -------------------------------------------------------------
console.log("\n[5. Typosquatting Detection Tests]");

test("Detects amaz0n.com (0 for o)", () => {
  const r = brandDetector.analyze("https://amaz0n.com/login");
  assertEqual(r.isImpersonation, true, "isImpersonation");
  assertEqual(r.threatType, "typosquatting", "threatType");
  assertEqual(r.brand, "Amazon", "brand");
});

test("Detects paypa1.com (1 for l)", () => {
  const r = brandDetector.analyze("https://paypa1.com/auth");
  assertEqual(r.isImpersonation, true, "isImpersonation");
  assertEqual(r.threatType, "typosquatting", "threatType");
  assertEqual(r.brand, "PayPal", "brand");
});

test("Detects g00gle.com (double 0 for o)", () => {
  const r = brandDetector.analyze("https://g00gle.com");
  assertEqual(r.isImpersonation, true, "isImpersonation");
  assertEqual(r.threatType, "typosquatting", "threatType");
  assertEqual(r.brand, "Google", "brand");
});

test("Detects amzon.com (missing letter edit distance 1)", () => {
  const r = brandDetector.analyze("https://amzon.com");
  assertEqual(r.isImpersonation, true, "isImpersonation");
  assertEqual(r.threatType, "typosquatting", "threatType");
  assertEqual(r.brand, "Amazon", "brand");
});

test("Detects gogle.com (missing letter edit distance 1)", () => {
  const r = brandDetector.analyze("https://gogle.com");
  assertEqual(r.isImpersonation, true, "isImpersonation");
  assertEqual(r.threatType, "typosquatting", "threatType");
  assertEqual(r.brand, "Google", "brand");
});

// -------------------------------------------------------------
// Suite 6: Combosquatting (Brand + Security/Login Keywords)
// -------------------------------------------------------------
console.log("\n[6. Combosquatting Detection Tests]");

test("Detects paypal-security-update.com", () => {
  const r = brandDetector.analyze("https://paypal-security-update.com");
  assertEqual(r.isImpersonation, true, "isImpersonation");
  assertEqual(r.threatType, "combosquatting", "threatType");
  assertEqual(r.brand, "PayPal", "brand");
});

test("Detects login-google-auth.com", () => {
  const r = brandDetector.analyze("https://login-google-auth.com");
  assertEqual(r.isImpersonation, true, "isImpersonation");
  assertEqual(r.threatType, "combosquatting", "threatType");
  assertEqual(r.brand, "Google", "brand");
});

test("Detects amazon-update-billing.net", () => {
  const r = brandDetector.analyze("https://amazon-update-billing.net");
  assertEqual(r.isImpersonation, true, "isImpersonation");
  assertEqual(r.threatType, "combosquatting", "threatType");
  assertEqual(r.brand, "Amazon", "brand");
});

// -------------------------------------------------------------
// Suite 7: IDN Homograph Attacks (Unicode Look-alikes)
// -------------------------------------------------------------
console.log("\n[7. IDN Homograph Attack Tests]");

test("Detects Cyrillic 'а' in аmazon.com", () => {
  // \u0430 is Cyrillic small letter a
  const r = brandDetector.analyze("https://\u0430mazon.com");
  assertEqual(r.isImpersonation, true, "isImpersonation");
  assertEqual(r.threatType, "homograph", "threatType");
  assertEqual(r.brand, "Amazon", "brand");
});

test("Detects Cyrillic 'о' in gооgle.com", () => {
  // \u043E is Cyrillic small letter o
  const r = brandDetector.analyze("https://g\u043E\u043Egle.com");
  assertEqual(r.isImpersonation, true, "isImpersonation");
  assertEqual(r.threatType, "homograph", "threatType");
  assertEqual(r.brand, "Google", "brand");
});

// -------------------------------------------------------------
// Suite 8: Legitimate Neutral Domains (Non-brands, non-impersonation)
// -------------------------------------------------------------
console.log("\n[8. Neutral Legitimate Domains Tests]");

test("Ignores unrelated legitimate domain (wikipedia.org)", () => {
  const r = brandDetector.analyze("https://en.wikipedia.org/wiki/Phishing");
  assertEqual(r.isImpersonation, false, "isImpersonation");
  assertEqual(r.isOfficial, false, "isOfficial");
  assertEqual(r.brand, null, "brand");
});

test("Ignores unrelated blog domain (mytechblog.com)", () => {
  const r = brandDetector.analyze("https://mytechblog.com/article/1");
  assertEqual(r.isImpersonation, false, "isImpersonation");
  assertEqual(r.isOfficial, false, "isOfficial");
});

// -------------------------------------------------------------
// Summary
// -------------------------------------------------------------
console.log("\n" + "=".repeat(60));
console.log(`Brand Impersonation Test Results: ${passed} passed, ${failed} failed`);
console.log("=".repeat(60) + "\n");

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
