/**
 * backend.test.js
 * ===============
 * Integration tests for the Express backend.
 *
 * These tests use Node's built-in http module and fetch API —
 * no extra test framework needed (no Jest/Mocha required).
 *
 * Run with:
 *   node backend/tests/backend.test.js
 *   or from inside backend/:
 *   node tests/backend.test.js
 *
 * The backend server must be running before you run these tests.
 * Start it with: node backend/server.js
 *
 * The ML service does NOT need to be running — we test both cases.
 */

const app = require("../app");

let BASE_URL = "http://localhost:3001";
let testServer = null;

let passed = 0;
let failed = 0;

// ------------------------------------------------------------------
// Simple test runner helpers
// ------------------------------------------------------------------
async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${err.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || "Assertion failed");
}

function assertEqual(actual, expected, label) {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

// ------------------------------------------------------------------
// HTTP helper
// ------------------------------------------------------------------
async function request(method, path, body = null) {
  const options = {
    method,
    headers: { "Content-Type": "application/json" },
  };
  if (body) options.body = JSON.stringify(body);

  const response = await fetch(`${BASE_URL}${path}`, options);
  const data = await response.json().catch(() => null);
  return { status: response.status, data };
}

// ------------------------------------------------------------------
// Test suites
// ------------------------------------------------------------------
async function runTests() {
  console.log("\n" + "=".repeat(50));
  console.log("PhishGuard Backend Tests");
  console.log("=".repeat(50));

  // --- Health endpoint ---
  console.log("\n[GET /api/health]");

  await test("Returns 200 status", async () => {
    const { status } = await request("GET", "/api/health");
    assertEqual(status, 200, "HTTP status");
  });

  await test("Response has status field", async () => {
    const { data } = await request("GET", "/api/health");
    assert("status" in data, "Missing 'status' field");
  });

  await test("Response has services.backend field", async () => {
    const { data } = await request("GET", "/api/health");
    assert(data.services?.backend?.status === "ok", "backend.status should be 'ok'");
  });

  // --- POST /api/scan — valid inputs ---
  console.log("\n[POST /api/scan — valid requests]");

  await test("Accepts a valid HTTPS URL", async () => {
    const { status, data } = await request("POST", "/api/scan", {
      url: "https://www.google.com",
    });
    // Could be 200 (success) or 503 (ML service down) — both are valid
    assert(
      status === 200 || status === 503 || status === 504,
      `Unexpected status: ${status}`
    );
    assert(typeof data === "object", "Response should be JSON");
  });

  await test("Returns expected fields on success (if ML service is up)", async () => {
    const { status, data } = await request("POST", "/api/scan", {
      url: "https://www.example.com",
    });
    if (status === 200) {
      assert("success" in data, "Missing 'success'");
      assert("prediction" in data, "Missing 'prediction'");
      assert("risk_score" in data, "Missing 'risk_score'");
      assert("risk_level" in data, "Missing 'risk_level'");
      assert(["phishing", "legitimate"].includes(data.prediction),
        `Invalid prediction: ${data.prediction}`);
      assert(typeof data.risk_score === "number", "risk_score must be a number");
      assert(data.risk_score >= 0 && data.risk_score <= 1,
        `risk_score out of range: ${data.risk_score}`);
      assert(["high", "medium", "low"].includes(data.risk_level),
        `Invalid risk_level: ${data.risk_level}`);
      assert("brand_analysis" in data, "Missing 'brand_analysis'");
      assert("is_impersonation" in data.brand_analysis, "Missing 'brand_analysis.is_impersonation'");
      assert("evidence" in data, "Missing 'evidence'");
      assert("explanation" in data, "Missing 'explanation'");
      assert("summary" in data.explanation, "Missing 'explanation.summary'");
      assert("tiers" in data.explanation, "Missing 'explanation.tiers'");
      assert("machine_learning" in data.explanation.tiers, "Missing 'machine_learning tier'");
      assert("heuristics" in data.explanation.tiers, "Missing 'heuristics tier'");
      assert("threat_intelligence" in data.explanation.tiers, "Missing 'threat_intelligence tier'");
    } else {
      console.log("    (ML service not running — skipping field validation)");
    }
  });

  await test("Flags brand impersonation in API response (if ML service is up)", async () => {
    const { status, data } = await request("POST", "/api/scan", {
      url: "https://amazon.com.example.net/login",
    });
    if (status === 200) {
      assert(data.brand_analysis?.is_impersonation === true, "Should flag misleading subdomain as impersonation");
      assertEqual(data.brand_analysis?.brand, "Amazon", "brand name");
      assertEqual(data.brand_analysis?.threat_type, "misleading_subdomain", "threat_type");
      assert(data.brand_analysis?.reasons?.length > 0, "Should include reasons");
      assertEqual(data.risk_level, "high", "Risk level should be high");
    } else {
      console.log("    (ML service not running — skipping impersonation API test)");
    }
  });

  // --- POST /api/scan — invalid inputs ---
  console.log("\n[POST /api/scan — invalid inputs]");

  await test("Rejects empty body", async () => {
    const { status, data } = await request("POST", "/api/scan", {});
    assertEqual(status, 400, "HTTP status for empty body");
    assert(data.success === false, "success should be false");
  });

  await test("Rejects missing url field", async () => {
    const { status, data } = await request("POST", "/api/scan", { noturl: "x" });
    assertEqual(status, 400, "HTTP status");
    assert(data.success === false, "success should be false");
  });

  await test("Rejects empty URL string", async () => {
    const { status, data } = await request("POST", "/api/scan", { url: "" });
    assertEqual(status, 400, "HTTP status for empty URL");
  });

  await test("Rejects chrome:// URL", async () => {
    const { status, data } = await request("POST", "/api/scan", {
      url: "chrome://settings",
    });
    assertEqual(status, 400, "HTTP status for chrome:// URL");
    assert(data.success === false, "success should be false");
  });

  await test("Rejects javascript: URL", async () => {
    const { status, data } = await request("POST", "/api/scan", {
      url: "javascript:alert(1)",
    });
    assertEqual(status, 400, "HTTP status for javascript: URL");
  });

  await test("Rejects URL that is too long", async () => {
    const longUrl = "https://example.com/" + "a".repeat(8000);
    const { status } = await request("POST", "/api/scan", { url: longUrl });
    assertEqual(status, 400, "HTTP status for overlong URL");
  });

  await test("Rejects non-string url value", async () => {
    const { status } = await request("POST", "/api/scan", { url: 12345 });
    assertEqual(status, 400, "HTTP status for non-string URL");
  });

  // --- 404 handler ---
  console.log("\n[404 handler]");

  await test("Unknown route returns 404", async () => {
    const { status } = await request("GET", "/api/nonexistent");
    assertEqual(status, 404, "HTTP status");
  });

  await test("Wrong method returns 404", async () => {
    const { status } = await request("GET", "/api/scan");
    // Express returns 404 for GET on a POST-only route
    assert(status === 404 || status === 405, `Unexpected status: ${status}`);
  });

  // --- Summary ---
  console.log("\n" + "=".repeat(50));
  console.log(`Results: ${passed} passed, ${failed} failed`);
  console.log("=".repeat(50) + "\n");

  if (failed > 0) {
    if (testServer) testServer.close();
    process.exit(1);
  }
  if (testServer) testServer.close();
}

// Check if backend is reachable before running tests, or launch in-process
fetch(`${BASE_URL}/api/health`)
  .then(() => runTests())
  .catch(() => {
    console.log(`Backend is not running on ${BASE_URL}. Starting in-process test server...`);
    testServer = app.listen(0, async () => {
      const port = testServer.address().port;
      BASE_URL = `http://localhost:${port}`;
      console.log(`In-process test server running on ${BASE_URL}`);
      await runTests();
    });
  });
