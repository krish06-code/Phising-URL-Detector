/**
 * rateLimiter.js
 * ==============
 * Limits how many requests a single IP address can make per minute.
 *
 * Why rate limit?
 * - Prevents someone from hammering the ML service with thousands of requests
 * - Protects against simple denial-of-service attacks
 * - Keeps the extension experience fair for all users
 *
 * For a Chrome extension used by one person locally, this limit is very generous.
 * If you deploy this publicly, lower the limits.
 */

const rateLimit = require("express-rate-limit");

// Main rate limiter: 100 requests per minute per IP
const scanLimiter = rateLimit({
  windowMs: 60 * 1000,  // 1 minute window
  max: 100,             // max 100 requests per window per IP
  standardHeaders: true, // Return rate limit info in the RateLimit-* headers
  legacyHeaders: false,  // Disable the X-RateLimit-* headers
  message: {
    success: false,
    error: "rate_limit_exceeded",
    message: "Too many requests. Please wait a moment before scanning again.",
  },
  // Skip rate limiting in test environments
  skip: () => process.env.NODE_ENV === "test",
});

module.exports = { scanLimiter };
