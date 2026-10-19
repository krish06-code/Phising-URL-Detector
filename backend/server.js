/**
 * server.js
 * =========
 * Entry point for the PhishGuard Node.js backend.
 *
 * Loads environment variables, imports the Express app,
 * and starts listening on the configured port.
 *
 * Start with:
 *   node backend/server.js
 * or from inside the backend/ folder:
 *   node server.js
 */

// Load .env file into process.env BEFORE importing anything else
// This ensures all modules see the environment variables
require("dotenv").config();

const app = require("./app");

const PORT = process.env.PORT || 3001;
const ML_SERVICE_URL = process.env.ML_SERVICE_URL || "http://localhost:8000";

// Start listening for incoming HTTP requests
const server = app.listen(PORT, () => {
  console.log("=".repeat(50));
  console.log("PhishGuard Backend Server");
  console.log("=".repeat(50));
  console.log(`Status:      Running`);
  console.log(`Port:        ${PORT}`);
  console.log(`ML Service:  ${ML_SERVICE_URL}`);
  console.log(`Environment: ${process.env.NODE_ENV || "development"}`);
  console.log("-".repeat(50));
  console.log(`Health check: http://localhost:${PORT}/api/health`);
  console.log(`Scan API:     POST http://localhost:${PORT}/api/scan`);
  console.log("=".repeat(50));
});

// Handle unexpected errors that bubble up to the top level
// (these would otherwise crash the server silently)
process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Promise Rejection:", reason);
  // Don't crash — just log it
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
  // For uncaught exceptions, it's safer to restart the process
  process.exit(1);
});

// Graceful shutdown — when Ctrl+C is pressed
process.on("SIGINT", () => {
  console.log("\nShutting down server gracefully...");
  server.close(() => {
    console.log("Server stopped.");
    process.exit(0);
  });
});

module.exports = server; // Export for testing
