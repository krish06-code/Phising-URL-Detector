/**
 * mlService.js
 * ============
 * Handles all communication with the Python FastAPI ML service.
 *
 * Why a separate service module?
 * - Keeps the controller clean — it just calls this module
 * - If we ever change the ML service URL or format, we only change here
 * - Makes it easier to add retry logic, caching, or circuit breaking later
 */

const axios = require("axios");

// Read ML service URL from environment variable (set in .env)
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || "http://localhost:8000";
const TIMEOUT_MS = parseInt(process.env.ML_SERVICE_TIMEOUT_MS || "10000", 10);

/**
 * Send a URL to the ML service and get back a prediction.
 *
 * @param {string} url - The URL to analyze
 * @returns {Promise<object>} - The ML service response object
 * @throws {Error} - If the ML service is unreachable or returns an error
 */
async function getPrediction(url) {
  try {
    const response = await axios.post(
      `${ML_SERVICE_URL}/predict`,
      { url },
      {
        timeout: TIMEOUT_MS,
        headers: { "Content-Type": "application/json" },
      }
    );

    // Validate the response structure before trusting it
    const data = response.data;

    if (!data || typeof data !== "object") {
      throw new Error("ML service returned an invalid response format");
    }

    if (!("prediction" in data) || !("risk_score" in data)) {
      throw new Error(
        "ML service response is missing required fields (prediction, risk_score)"
      );
    }

    if (!["phishing", "legitimate"].includes(data.prediction)) {
      throw new Error(
        `ML service returned unexpected prediction value: '${data.prediction}'`
      );
    }

    if (typeof data.risk_score !== "number" || data.risk_score < 0 || data.risk_score > 1) {
      throw new Error(
        `ML service returned invalid risk_score: ${data.risk_score}`
      );
    }

    return data;
  } catch (err) {
    // Translate axios/network errors into descriptive messages
    if (err.code === "ECONNREFUSED") {
      const error = new Error(
        `Cannot connect to ML service at ${ML_SERVICE_URL}. ` +
        "Make sure the Python ML service is running (uvicorn ml-service.app:app --port 8000)."
      );
      error.code = "ML_SERVICE_UNAVAILABLE";
      throw error;
    }

    if (err.code === "ETIMEDOUT" || err.code === "ECONNABORTED") {
      const error = new Error(
        `ML service did not respond within ${TIMEOUT_MS}ms. It may be overloaded.`
      );
      error.code = "ML_SERVICE_TIMEOUT";
      throw error;
    }

    if (err.response) {
      // The ML service responded with an HTTP error (4xx or 5xx)
      const detail = err.response.data?.detail;
      const mlError = typeof detail === "object"
        ? detail.message
        : (detail || "ML service error");

      const error = new Error(`ML service error: ${mlError}`);
      error.code = "ML_SERVICE_ERROR";
      error.statusCode = err.response.status;
      throw error;
    }

    // Re-throw if it was already our custom error or an unknown error
    throw err;
  }
}

/**
 * Check if the ML service is reachable and its model is loaded.
 *
 * @returns {Promise<{reachable: boolean, modelLoaded: boolean, modelVersion: string}>}
 */
async function checkHealth() {
  try {
    const response = await axios.get(`${ML_SERVICE_URL}/health`, {
      timeout: 5000, // shorter timeout for health checks
    });
    const data = response.data;
    return {
      reachable: true,
      modelLoaded: data.model_loaded === true,
      modelVersion: data.model_version || "unknown",
      status: data.status,
    };
  } catch {
    return { reachable: false, modelLoaded: false, modelVersion: "unknown" };
  }
}

module.exports = { getPrediction, checkHealth };
