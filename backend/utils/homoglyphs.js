/**
 * homoglyphs.js
 * =============
 * Utilities for detecting Unicode homoglyph attacks (IDN spoofing),
 * leetspeak / character substitutions, and computing string similarity.
 *
 * Attackers exploit visually indistinguishable characters from other scripts
 * (e.g. Cyrillic 'а' U+0430 looks identical to Latin 'a' U+0061) or common
 * character substitutions (e.g. '0' for 'o', '1' for 'l').
 */

// Mapping of common confusable Unicode characters to their Latin equivalents
const UNICODE_HOMOGLYPH_MAP = {
  // Cyrillic look-alikes
  "\u0430": "a", // Cyrillic small letter a
  "\u0410": "a", // Cyrillic capital letter A
  "\u0441": "c", // Cyrillic small letter es
  "\u0421": "c", // Cyrillic capital letter Es
  "\u0435": "e", // Cyrillic small letter ie
  "\u0415": "e", // Cyrillic capital letter Ie
  "\u0456": "i", // Cyrillic small letter byelorussian-ukrainian i
  "\u0406": "i", // Cyrillic capital letter Byelorussian-Ukrainian I
  "\u0458": "j", // Cyrillic small letter je
  "\u0440": "p", // Cyrillic small letter er
  "\u0420": "p", // Cyrillic capital letter Er
  "\u043E": "o", // Cyrillic small letter o
  "\u041E": "o", // Cyrillic capital letter O
  "\u0455": "s", // Cyrillic small letter dze
  "\u0445": "x", // Cyrillic small letter ha
  "\u0425": "x", // Cyrillic capital letter Ha
  "\u0443": "y", // Cyrillic small letter u
  "\u0423": "y", // Cyrillic capital letter U
  "\u0432": "b", // Cyrillic small letter ve (looks like b)
  "\u043A": "k", // Cyrillic small letter ka
  "\u041A": "k", // Cyrillic capital letter Ka
  "\u043C": "m", // Cyrillic small letter em
  "\u041C": "m", // Cyrillic capital letter Em
  "\u043D": "h", // Cyrillic small letter en (looks like H)
  "\u0442": "t", // Cyrillic capital/small te

  // Greek look-alikes
  "\u03B1": "a", // Greek small letter alpha
  "\u03BF": "o", // Greek small letter omicron
  "\u039F": "o", // Greek capital letter Omicron
  "\u03BD": "v", // Greek small letter nu (looks like v)
  "\u03C1": "p", // Greek small letter rho (looks like p)
  "\u03C4": "t", // Greek small letter tau
  "\u03B9": "i", // Greek small letter iota
  "\u03BA": "k", // Greek small letter kappa
  "\u03B5": "e", // Greek small letter epsilon

  // Other common confusable symbols
  "\u2010": "-", // Hyphen
  "\u2011": "-", // Non-breaking hyphen
  "\u2012": "-", // Figure dash
  "\u2013": "-", // En dash
  "\u2014": "-", // Em dash
  "\uFF0E": ".", // Fullwidth full stop
  "\u3002": ".", // Ideographic full stop
};

// Common leetspeak substitutions used in typosquatting
const LEETSPEAK_MAP = {
  "0": "o",
  "1": "l", // can also be 'i'
  "3": "e",
  "4": "a",
  "5": "s",
  "8": "b",
  "@": "a",
  "$": "s",
  "!": "i",
};

/**
 * Normalizes a string by mapping Unicode homoglyphs to their Latin equivalents.
 * Also reports whether any suspicious non-ASCII look-alikes were detected.
 *
 * @param {string} str - String to normalize
 * @returns {{ normalized: string, hasHomoglyphs: boolean, replacedChars: string[] }}
 */
function normalizeHomoglyphs(str) {
  if (!str) return { normalized: "", hasHomoglyphs: false, replacedChars: [] };

  let normalized = "";
  let hasHomoglyphs = false;
  const replacedChars = [];

  for (const char of str) {
    if (UNICODE_HOMOGLYPH_MAP[char]) {
      normalized += UNICODE_HOMOGLYPH_MAP[char];
      hasHomoglyphs = true;
      replacedChars.push(char);
    } else {
      normalized += char;
    }
  }

  return {
    normalized: normalized.toLowerCase(),
    hasHomoglyphs,
    replacedChars,
  };
}

/**
 * Generates leetspeak-normalized variations of a string.
 * e.g. "amaz0n" -> "amazon", "paypa1" -> "paypal" or "paypai"
 *
 * @param {string} str - String containing possible leetspeak
 * @returns {string[]} Array of possible normalized candidates
 */
function normalizeLeetspeak(str) {
  if (!str) return [];
  const lower = str.toLowerCase();

  // Primary replacement: 0->o, 1->l, 3->e, 4->a, 5->s, 8->b
  let primary = "";
  let secondary = ""; // alternate 1 -> i
  let hadSubstitution = false;

  for (const char of lower) {
    if (LEETSPEAK_MAP[char]) {
      hadSubstitution = true;
      primary += LEETSPEAK_MAP[char];
      secondary += char === "1" ? "i" : LEETSPEAK_MAP[char];
    } else {
      primary += char;
      secondary += char;
    }
  }

  // Also handle double-v ('vv' -> 'w') and 'rn' -> 'm'
  const variations = new Set();
  if (hadSubstitution) {
    variations.add(primary);
    variations.add(secondary);
  }

  // Look for visual digraph confusions:
  // "vv" looks like "w" (e.g. vvww -> www)
  if (lower.includes("vv")) {
    variations.add(lower.replace(/vv/g, "w"));
    if (primary) variations.add(primary.replace(/vv/g, "w"));
  }
  // "rn" looks like "m" (e.g. rnicrosoft -> microsoft)
  if (lower.includes("rn")) {
    variations.add(lower.replace(/rn/g, "m"));
    if (primary) variations.add(primary.replace(/rn/g, "m"));
  }

  return Array.from(variations).filter((v) => v !== lower);
}

/**
 * Computes Levenshtein distance between two strings.
 * Used to measure edit distance for typosquatting detection.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number} The edit distance
 */
function levenshteinDistance(a, b) {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;

  const row = Array.from({ length: b.length + 1 }, (_, i) => i);

  for (let i = 1; i <= a.length; i++) {
    let prev = i;
    for (let j = 1; j <= b.length; j++) {
      const val = a[i - 1] === b[j - 1] ? row[j - 1] : Math.min(row[j - 1], row[j], prev) + 1;
      row[j - 1] = prev;
      prev = val;
    }
    row[b.length] = prev;
  }

  return row[b.length];
}

module.exports = {
  UNICODE_HOMOGLYPH_MAP,
  LEETSPEAK_MAP,
  normalizeHomoglyphs,
  normalizeLeetspeak,
  levenshteinDistance,
};
