/**
 * validators.js
 * =============
 * URL validation utilities shared across the backend.
 *
 * Why validate here AND in the ML service?
 * - Defense in depth: catch bad input as early as possible
 * - The Node.js backend is the user-facing layer; give clear errors here
 * - The ML service validates again as a safety net
 */

// Maximum URL length we will accept from the extension
const MAX_URL_LENGTH = 8000;

// URL schemes we support
const ALLOWED_SCHEMES = ["http:", "https:", "ftp:"];

/**
 * Validates a URL string before forwarding it to the ML service.
 *
 * Returns: { valid: true } on success
 *          { valid: false, reason: "explanation" } on failure
 */
function validateUrl(url) {
  // Must be a non-empty string
  if (typeof url !== "string") {
    return { valid: false, reason: "URL must be a string" };
  }

  const trimmed = url.trim();

  if (trimmed.length === 0) {
    return { valid: false, reason: "URL cannot be empty" };
  }

  if (trimmed.length > MAX_URL_LENGTH) {
    return {
      valid: false,
      reason: `URL is too long (${trimmed.length} chars). Max allowed: ${MAX_URL_LENGTH}`,
    };
  }

  // Parse the URL using the built-in URL constructor
  // This is more reliable than regex for URL validation
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, reason: "URL is not a valid URL format" };
  }

  // Only allow http/https/ftp — reject chrome://, file://, javascript:, etc.
  if (!ALLOWED_SCHEMES.includes(parsed.protocol)) {
    return {
      valid: false,
      reason: `Unsupported URL scheme '${parsed.protocol}'. Only http and https are accepted.`,
    };
  }

  // Must have an actual hostname (not just a path)
  if (!parsed.hostname) {
    return { valid: false, reason: "URL must include a hostname" };
  }

  return { valid: true };
}

/**
 * Validates the full request body for POST /api/scan.
 * Returns { valid: true } or { valid: false, reason: "..." }
 */
function validateScanRequestBody(body) {
  if (!body || typeof body !== "object") {
    return { valid: false, reason: "Request body must be a JSON object" };
  }

  if (!("url" in body)) {
    return { valid: false, reason: "Request body must include a 'url' field" };
  }

  return validateUrl(body.url);
}

module.exports = { validateUrl, validateScanRequestBody, MAX_URL_LENGTH };
