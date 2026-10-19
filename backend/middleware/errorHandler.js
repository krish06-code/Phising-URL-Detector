/**
 * errorHandler.js
 * ===============
 * Centralized error handling middleware for Express.
 *
 * Express recognizes this as an error handler because it takes 4 arguments
 * (err, req, res, next). Any route that calls next(err) ends up here.
 *
 * Why centralize error handling?
 * - Consistent error response format for all errors
 * - Prevents stack traces from leaking to the client
 * - Single place to add logging, monitoring, or alerting later
 */

/**
 * Maps our custom error codes to HTTP status codes.
 */
const ERROR_STATUS_MAP = {
  ML_SERVICE_UNAVAILABLE: 503,
  ML_SERVICE_TIMEOUT: 504,
  ML_SERVICE_ERROR: 502,
};

/**
 * Express error handler middleware.
 * Must be registered AFTER all routes in app.js.
 */
function errorHandler(err, req, res, next) { // eslint-disable-line no-unused-vars
  // Determine HTTP status code
  const statusCode = err.statusCode || ERROR_STATUS_MAP[err.code] || 500;

  // Build a safe error message — never expose internal stack traces
  let userMessage;
  if (err.code === "ML_SERVICE_UNAVAILABLE") {
    userMessage =
      "The analysis service is currently unavailable. " +
      "Please make sure the ML service is running and try again.";
  } else if (err.code === "ML_SERVICE_TIMEOUT") {
    userMessage =
      "The analysis service took too long to respond. Please try again.";
  } else if (err.code === "ML_SERVICE_ERROR") {
    userMessage =
      "The analysis service returned an error. The model may not be trained yet.";
  } else {
    userMessage = "An unexpected error occurred. Please try again.";
  }

  // Log the actual error internally (do NOT send stack trace to client)
  // In production, replace console.error with a proper logger like winston
  if (process.env.NODE_ENV !== "test") {
    console.error(`[ERROR] ${err.code || "UNKNOWN"}: ${err.message}`);
  }

  res.status(statusCode).json({
    success: false,
    error: err.code || "internal_error",
    message: userMessage,
  });
}

module.exports = errorHandler;
