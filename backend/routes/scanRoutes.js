/**
 * scanRoutes.js
 * =============
 * Defines the URL routing for the /api endpoints.
 *
 * Keeping routes in a separate file makes the code organized:
 * - server.js sets up the server
 * - app.js sets up Express + middleware
 * - routes/*.js define URL paths
 * - controllers/*.js handle the actual request logic
 */

const express = require("express");
const router = express.Router();
const { healthCheck, scanUrl } = require("../controllers/scanController");

// GET /api/health  — check if backend and ML service are running
router.get("/health", healthCheck);

// POST /api/scan  — submit a URL for phishing analysis
router.post("/scan", scanUrl);

module.exports = router;
