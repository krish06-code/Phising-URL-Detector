/**
 * domainParser.js
 * ===============
 * Robust domain and URL parser that distinguishes:
 * - Actual registered domain (eTLD+1)
 * - Subdomain
 * - Main domain (SLD)
 * - Public suffix / TLD
 * - Punycode (IDN) decoding
 *
 * Examples:
 *   "https://amazon.com.example.net/login"
 *     -> hostname: "amazon.com.example.net"
 *     -> registeredDomain: "example.net"
 *     -> mainDomain: "example"
 *     -> subdomain: "amazon.com"
 *     -> tld: "net"
 *
 *   "https://sub.paypa1.co.uk/verify"
 *     -> hostname: "sub.paypa1.co.uk"
 *     -> registeredDomain: "paypa1.co.uk"
 *     -> mainDomain: "paypa1"
 *     -> subdomain: "sub"
 *     -> tld: "co.uk"
 */

const { domainToUnicode } = require("url");

// Common multi-part public suffixes (eTLDs) to avoid incorrectly treating
// .co.uk, .com.au, etc. as registered domains
const MULTI_PART_SUFFIXES = new Set([
  "co.uk",
  "org.uk",
  "gov.uk",
  "ac.uk",
  "me.uk",
  "net.uk",
  "com.au",
  "net.au",
  "org.au",
  "edu.au",
  "gov.au",
  "co.nz",
  "net.nz",
  "org.nz",
  "govt.nz",
  "co.jp",
  "ne.jp",
  "ac.jp",
  "go.jp",
  "or.jp",
  "co.in",
  "net.in",
  "org.in",
  "gen.in",
  "ind.in",
  "firm.in",
  "gov.in",
  "edu.in",
  "com.br",
  "net.br",
  "org.br",
  "gov.br",
  "com.mx",
  "edu.mx",
  "gob.mx",
  "org.mx",
  "co.za",
  "org.za",
  "gov.za",
  "com.sg",
  "edu.sg",
  "gov.sg",
  "com.tw",
  "org.tw",
  "gov.tw",
  "com.hk",
  "org.hk",
  "gov.hk",
  "co.kr",
  "ne.kr",
  "re.kr",
  "com.cn",
  "net.cn",
  "org.cn",
  "gov.cn",
  "co.id",
  "web.id",
  "sch.id",
  "com.my",
  "net.my",
  "org.my",
  "gov.my",
  "com.ph",
  "net.ph",
  "org.ph",
  "gov.ph",
  "com.tr",
  "org.tr",
  "gov.tr",
  "com.ru",
  "net.ru",
  "org.ru",
  "co.il",
  "org.il",
]);

/**
 * Checks if a string is an IPv4 or IPv6 address.
 *
 * @param {string} hostname
 * @returns {boolean}
 */
function isIpAddress(hostname) {
  if (!hostname) return false;
  // IPv4 check
  const ipv4Regex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  if (ipv4Regex.test(hostname)) {
    const parts = hostname.split(".");
    return parts.every((p) => {
      const n = Number(p);
      return n >= 0 && n <= 255;
    });
  }
  // IPv6 bracketed or raw hex check
  if (hostname.startsWith("[") && hostname.endsWith("]")) return true;
  if ((hostname.match(/:/g) || []).length >= 2) return true;
  return false;
}

/**
 * Parses a URL and extracts its domain components accurately.
 *
 * @param {string} rawUrl
 * @returns {object|null} Parsed domain information or null if invalid
 */
function parseDomain(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") return null;

  let urlObj;
  try {
    // If scheme is missing, prepend https:// for parsing
    const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(rawUrl);
    const urlStringToParse = hasScheme ? rawUrl : `https://${rawUrl}`;
    urlObj = new URL(urlStringToParse);
  } catch {
    return null;
  }

  // Extract hostname (remove port and convert to lowercase)
  let hostname = urlObj.hostname.toLowerCase().trim();
  // Strip trailing dot if present (FQDN)
  if (hostname.endsWith(".")) {
    hostname = hostname.slice(0, -1);
  }

  if (!hostname) return null;

  const isIp = isIpAddress(hostname);
  const isPunycode = hostname.includes("xn--");
  const unicodeHostname = isPunycode ? domainToUnicode(hostname) : hostname;

  if (isIp) {
    return {
      isValid: true,
      rawUrl,
      protocol: urlObj.protocol,
      hostname,
      unicodeHostname,
      isIp: true,
      isPunycode: false,
      registeredDomain: hostname,
      mainDomain: hostname,
      subdomain: "",
      tld: "",
      pathname: urlObj.pathname,
    };
  }

  // Split hostname parts
  const parts = hostname.split(".");

  if (parts.length === 1) {
    // Localhost or single word domain
    return {
      isValid: true,
      rawUrl,
      protocol: urlObj.protocol,
      hostname,
      unicodeHostname,
      isIp: false,
      isPunycode,
      registeredDomain: hostname,
      mainDomain: hostname,
      subdomain: "",
      tld: "",
      pathname: urlObj.pathname,
    };
  }

  // Check for multi-part public suffix at the end (e.g. co.uk, com.au)
  let tld = "";
  let registeredDomain = "";
  let mainDomain = "";
  let subdomain = "";

  const lastTwo = parts.slice(-2).join(".");
  if (parts.length >= 3 && MULTI_PART_SUFFIXES.has(lastTwo)) {
    // Registered domain needs the 3rd part from right: e.g. "amazon.co.uk"
    tld = lastTwo;
    mainDomain = parts[parts.length - 3];
    registeredDomain = `${mainDomain}.${tld}`;
    const subParts = parts.slice(0, parts.length - 3);
    subdomain = subParts.join(".");
  } else {
    // Standard single-part TLD: e.g. "example.com"
    tld = parts[parts.length - 1];
    mainDomain = parts[parts.length - 2];
    registeredDomain = `${mainDomain}.${tld}`;
    const subParts = parts.slice(0, parts.length - 2);
    subdomain = subParts.join(".");
  }

  return {
    isValid: true,
    rawUrl,
    protocol: urlObj.protocol,
    hostname,
    unicodeHostname,
    isIp: false,
    isPunycode,
    registeredDomain,
    mainDomain,
    subdomain,
    tld,
    pathname: urlObj.pathname,
  };
}

module.exports = {
  parseDomain,
  isIpAddress,
  MULTI_PART_SUFFIXES,
};
