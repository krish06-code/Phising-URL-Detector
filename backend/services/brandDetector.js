/**
 * brandDetector.js
 * ================
 * Comprehensive brand impersonation detection engine.
 *
 * Identifies malicious URLs that attempt to imitate protected brands
 * using:
 * 1. Misleading subdomains (e.g. amazon.com.example.net)
 * 2. Typosquatting (e.g. amzon.com, gogle.com, paypaal.com)
 * 3. Leetspeak / character substitutions (e.g. amaz0n.com, paypa1.com)
 * 4. Combosquatting (e.g. paypal-security-update.com, login-google.com)
 * 5. IDN Homograph attacks / Punycode (e.g. Cyrillic look-alikes)
 *
 * Crucially:
 * - Differentiates legitimate official domains from fake ones
 * - Accurately extracts registered domain (eTLD+1) vs subdomains
 * - Explains EXACTLY why a domain was flagged
 */

const { PROTECTED_BRANDS, SUSPICIOUS_AFFIXES } = require("../config/brands");
const { parseDomain } = require("../utils/domainParser");
const {
  normalizeHomoglyphs,
  normalizeLeetspeak,
  levenshteinDistance,
} = require("../utils/homoglyphs");

class BrandDetector {
  constructor(brands = PROTECTED_BRANDS, affixes = SUSPICIOUS_AFFIXES) {
    this.brands = brands;
    this.affixes = affixes;
    this.officialDomainSet = new Set();

    // Index official domains for fast lookup
    for (const b of this.brands) {
      for (const d of b.officialDomains) {
        this.officialDomainSet.add(d.toLowerCase());
      }
    }
  }

  /**
   * Check if a parsed domain is an official domain of a given brand.
   *
   * @param {object} parsed - Result of parseDomain
   * @param {object} brand - Brand definition object
   * @returns {boolean}
   */
  isOfficialDomain(parsed, brand) {
    if (!parsed || !parsed.registeredDomain) return false;

    const reg = parsed.registeredDomain.toLowerCase();
    const host = parsed.hostname.toLowerCase();

    for (const official of brand.officialDomains) {
      const offLower = official.toLowerCase();
      // Exact match on registered domain
      if (reg === offLower) return true;
      // Hostname matches or is a subdomain of official (e.g., aws.amazon.com)
      if (host === offLower || host.endsWith(`.${offLower}`)) return true;
    }

    return false;
  }

  /**
   * Checks if a domain is official for ANY protected brand.
   *
   * @param {object} parsed
   * @returns {{ isOfficial: boolean, brand: object|null }}
   */
  findOfficialBrand(parsed) {
    for (const brand of this.brands) {
      if (this.isOfficialDomain(parsed, brand)) {
        return { isOfficial: true, brand };
      }
    }
    return { isOfficial: false, brand: null };
  }

  /**
   * Main analysis function: inspects a URL for brand impersonation.
   *
   * @param {string} rawUrl - The URL to analyze
   * @returns {object} Analysis result
   */
  analyze(rawUrl) {
    const parsed = parseDomain(rawUrl);

    if (!parsed || !parsed.isValid) {
      return {
        isImpersonation: false,
        isOfficial: false,
        brand: null,
        threatType: null,
        confidence: "none",
        reasons: [],
        warning: null,
        officialDomains: [],
        details: null,
      };
    }

    // Step 1: Check if this is an official domain of any protected brand
    const officialCheck = this.findOfficialBrand(parsed);
    if (officialCheck.isOfficial) {
      return {
        isImpersonation: false,
        isOfficial: true,
        brand: officialCheck.brand.name,
        threatType: null,
        confidence: "verified",
        reasons: [`Verified official domain of ${officialCheck.brand.name}`],
        warning: null,
        officialDomains: officialCheck.brand.officialDomains,
        details: {
          hostname: parsed.hostname,
          registeredDomain: parsed.registeredDomain,
        },
      };
    }

    // Step 2: Not an official domain. Evaluate against all protected brands for impersonation
    const findings = [];

    for (const brand of this.brands) {
      const brandFindings = this.evaluateBrandImpersonation(parsed, brand);
      if (brandFindings) {
        findings.push(brandFindings);
      }
    }

    if (findings.length === 0) {
      return {
        isImpersonation: false,
        isOfficial: false,
        brand: null,
        threatType: null,
        confidence: "none",
        reasons: [],
        warning: null,
        officialDomains: [],
        details: {
          hostname: parsed.hostname,
          registeredDomain: parsed.registeredDomain,
        },
      };
    }

    // Pick the highest confidence/priority finding
    // Priority order: homograph > misleading_subdomain > typosquatting > combosquatting
    const priority = {
      homograph: 4,
      misleading_subdomain: 3,
      typosquatting: 2,
      combosquatting: 1,
    };

    findings.sort((a, b) => (priority[b.threatType] || 0) - (priority[a.threatType] || 0));
    const topFinding = findings[0];

    return {
      isImpersonation: true,
      isOfficial: false,
      brand: topFinding.brand.name,
      brandId: topFinding.brand.id,
      threatType: topFinding.threatType,
      confidence: topFinding.confidence,
      reasons: topFinding.reasons,
      warning: topFinding.warning,
      officialDomains: topFinding.brand.officialDomains,
      details: {
        hostname: parsed.hostname,
        registeredDomain: parsed.registeredDomain,
        subdomain: parsed.subdomain,
        mainDomain: parsed.mainDomain,
        matchedKeyword: topFinding.matchedKeyword,
      },
    };
  }

  /**
   * Evaluates a single brand against a parsed domain.
   *
   * @param {object} parsed
   * @param {object} brand
   * @returns {object|null}
   */
  evaluateBrandImpersonation(parsed, brand) {
    const main = parsed.mainDomain.toLowerCase();
    const sub = parsed.subdomain.toLowerCase();
    const host = parsed.hostname.toLowerCase();
    const unicodeMain = (parsed.unicodeHostname || "").split(".")[0] || main;

    // -------------------------------------------------------------
    // Check 1: Misleading Subdomains
    // e.g. amazon.com.example.net, paypal.com.verify-account.org
    // -------------------------------------------------------------
    for (const official of brand.officialDomains) {
      const offLower = official.toLowerCase();
      // Does subdomain exactly equal or end with official domain?
      if (sub === offLower || sub.endsWith(`.${offLower}`) || sub.endsWith(`-${offLower}`)) {
        return {
          brand,
          threatType: "misleading_subdomain",
          confidence: "high",
          matchedKeyword: official,
          reasons: [
            `The official domain '${official}' appears inside the subdomain, but the actual website you are visiting is '${parsed.registeredDomain}'.`,
          ],
          warning: `Misleading subdomain masquerading as ${brand.name}. Real destination: ${parsed.registeredDomain}.`,
        };
      }
    }

    // Check if brand keywords appear prominently as subdomain segments
    for (const kw of brand.keywords) {
      const subSegments = sub.split(/[.-]/);
      if (subSegments.includes(kw)) {
        return {
          brand,
          threatType: "misleading_subdomain",
          confidence: "high",
          matchedKeyword: kw,
          reasons: [
            `Subdomain '${parsed.subdomain}' contains brand name '${kw}', while the actual registered domain is '${parsed.registeredDomain}'.`,
          ],
          warning: `Subdomain mimics ${brand.name}. The actual registered domain is ${parsed.registeredDomain}.`,
        };
      }
    }

    // -------------------------------------------------------------
    // Check 2: IDN Homograph / Unicode Look-alike Attack
    // e.g. Cyrillic 'а' in аmazon.com or xn--gogle-pqa.com
    // -------------------------------------------------------------
    const homoglyphResult = normalizeHomoglyphs(parsed.unicodeHostname);
    if (homoglyphResult.hasHomoglyphs) {
      for (const kw of brand.keywords) {
        if (homoglyphResult.normalized.includes(kw)) {
          return {
            brand,
            threatType: "homograph",
            confidence: "high",
            matchedKeyword: kw,
            reasons: [
              `Domain uses visually deceptive Unicode look-alike characters (${homoglyphResult.replacedChars.join(
                ", "
              )}) to imitate '${brand.name}'.`,
            ],
            warning: `IDN Homograph attack detected: This domain uses fake Unicode letters that visually mimic ${brand.name}.`,
          };
        }
      }
    }

    // -------------------------------------------------------------
    // Check 3: Typosquatting via Leetspeak / Character Substitution
    // e.g. amaz0n.com, paypa1.com, g00gle.com, m1crosoft.com
    // -------------------------------------------------------------
    const leetspeakVariants = normalizeLeetspeak(main);
    for (const variant of leetspeakVariants) {
      for (const kw of brand.keywords) {
        if (variant === kw) {
          return {
            brand,
            threatType: "typosquatting",
            confidence: "high",
            matchedKeyword: kw,
            reasons: [
              `Domain '${main}' substitutes characters (such as 0 for o, 1 for l) to imitate the brand '${brand.name}'.`,
            ],
            warning: `Typosquatting detected: '${main}' is a visual imitation of ${brand.name}.`,
          };
        }
      }
    }

    // -------------------------------------------------------------
    // Check 4: Typosquatting via Edit Distance (Levenshtein)
    // e.g. amzon.com, gogle.com, paypaal.com, microsft.com
    // -------------------------------------------------------------
    for (const kw of brand.keywords) {
      if (kw.length >= 4 && main !== kw) {
        const dist = levenshteinDistance(main, kw);

        // Edit distance 1 is a strong typosquatting indicator for brand keywords
        // (e.g. amzon [len 5 vs 6] dist=1, gogle [len 5 vs 6] dist=1, paypaal [len 7 vs 6] dist=1)
        if (dist === 1 && Math.abs(main.length - kw.length) <= 1) {
          return {
            brand,
            threatType: "typosquatting",
            confidence: "high",
            matchedKeyword: kw,
            reasons: [
              `Domain '${main}' is 1 character away from the official brand name '${kw}' (edit distance 1).`,
            ],
            warning: `Typosquatting detected: '${main}' closely mimics the spelling of ${brand.name}.`,
          };
        }

        // For longer keywords (>= 8 chars like microsoft), distance of 2 can be a typo (e.g. microsfot)
        if (kw.length >= 8 && dist === 2 && Math.abs(main.length - kw.length) <= 1) {
          return {
            brand,
            threatType: "typosquatting",
            confidence: "medium",
            matchedKeyword: kw,
            reasons: [
              `Domain '${main}' is very close to the brand name '${kw}' (transposition or slight misspelling).`,
            ],
            warning: `Possible typosquatting: '${main}' closely resembles ${brand.name}.`,
          };
        }
      }
    }

    // -------------------------------------------------------------
    // Check 5: Combosquatting (Brand keyword + security/login affix)
    // e.g. paypal-security-update.com, login-amazon-auth.net
    // -------------------------------------------------------------
    for (const kw of brand.keywords) {
      // Must contain brand keyword and a hyphen or affix
      if (main.includes(kw) && main !== kw) {
        // Check if paired with suspicious affix or hyphenated
        const hasHyphen = main.includes(`-${kw}`) || main.includes(`${kw}-`);
        const matchedAffix = this.affixes.find((affix) => main.includes(affix));

        if (hasHyphen || matchedAffix) {
          const detailStr = matchedAffix
            ? `combines '${kw}' with the keyword '${matchedAffix}'`
            : `combines brand '${kw}' with deceptive hyphenated wording`;

          return {
            brand,
            threatType: "combosquatting",
            confidence: "high",
            matchedKeyword: kw,
            reasons: [
              `Domain '${parsed.registeredDomain}' ${detailStr}, but is NOT an official domain of ${brand.name}.`,
            ],
            warning: `Combosquatting detected: This domain pairs the ${brand.name} brand name with security/account terms.`,
          };
        }
      }
    }

    return null;
  }
}

// Export singleton instance as well as class
const defaultDetector = new BrandDetector();

module.exports = {
  BrandDetector,
  brandDetector: defaultDetector,
};
