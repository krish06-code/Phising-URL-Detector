/**
 * app.js
 * ======
 * Creates and configures the Express application.
 *
 * Separation of concerns:
 * - app.js    = Express config, middleware, routes
 * - server.js = Starting the HTTP server (listening on a port)
 *
 * This separation makes it easier to test the app without
 * starting a real server.
 */

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const { scanLimiter } = require("./middleware/rateLimiter");
const errorHandler = require("./middleware/errorHandler");
const scanRoutes = require("./routes/scanRoutes");

const app = express();

// ------------------------------------------------------------------
// Security headers (helmet adds headers like X-Frame-Options,
// Content-Security-Policy, etc. to protect against common attacks)
// ------------------------------------------------------------------
app.use(helmet());

// ------------------------------------------------------------------
// CORS (Cross-Origin Resource Sharing)
//
// The Chrome extension uses the chrome-extension:// scheme.
// We need to allow that origin so the extension can call our API.
// We also allow localhost for development/testing with curl or Postman.
//
// We do NOT use wildcard (*) because that would allow any website
// to make requests to our backend.
// ------------------------------------------------------------------
const allowedOrigins = [
  // Chrome extension origin — replace YOUR_EXTENSION_ID after loading in Chrome
  /^chrome-extension:\/\//,
  "http://localhost:3001",
  "http://127.0.0.1:3001",
  // Allow no-origin requests (e.g., curl, Postman) in development
  ...(process.env.NODE_ENV === "development" ? [undefined, null] : []),
];

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (like curl) in development
      if (!origin && process.env.NODE_ENV === "development") {
        return callback(null, true);
      }
      // Allow chrome extensions
      if (origin && origin.startsWith("chrome-extension://")) {
        return callback(null, true);
      }
      // Allow explicit allowed origins
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      callback(new Error(`CORS: origin '${origin}' not allowed`));
    },
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"],
  })
);

// ------------------------------------------------------------------
// Body parsing — limit request size to 16KB to prevent large payloads
// ------------------------------------------------------------------
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: false, limit: "16kb" }));

// ------------------------------------------------------------------
// Apply rate limiting to all API routes
// ------------------------------------------------------------------
app.use("/api", scanLimiter);

// ------------------------------------------------------------------
// API Routes
// ------------------------------------------------------------------
app.use("/api", scanRoutes);

// ------------------------------------------------------------------
// 404 handler — for any path that doesn't match our routes
// ------------------------------------------------------------------
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "not_found",
    message: `Route ${req.method} ${req.path} does not exist`,
  });
});

// ------------------------------------------------------------------
// Centralized error handler — must be LAST middleware registered
// ------------------------------------------------------------------
app.use(errorHandler);

module.exports = app;
