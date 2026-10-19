/**
 * background.js
 * =============
 * The extension's background service worker (Manifest V3).
 *
 * A service worker runs in the background (not tied to any tab/window).
 * It's responsible for:
 * - Listening for messages from popup.js
 * - Making HTTP requests to the backend (popup can't do CORS easily)
 * - Caching recent scan results so we don't re-scan the same URL
 *
 * Note: Service workers in MV3 are terminated when idle and restarted
 * when needed. Don't rely on in-memory state surviving between invocations.
 * Use chrome.storage instead for persistent data.
 */

// URL of the Node.js Express backend
// Change this if you deploy the backend to a remote server
const BACKEND_URL = "http://localhost:3001";

// How long to cache a scan result (in milliseconds)
// We re-scan if more than 5 minutes have passed
const CACHE_DURATION_MS = 5 * 60 * 1000;

// ------------------------------------------------------------------
// Message listener — popup.js sends messages to us here
// ------------------------------------------------------------------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "SCAN_URL") {
    // Handle async response properly in MV3
    handleScanUrl(message.url)
      .then((result) => sendResponse({ success: true, data: result }))
      .catch((err) => sendResponse({ success: false, error: err.message }));

    // Return true to tell Chrome we'll call sendResponse asynchronously
    return true;
  }

  if (message.type === "CHECK_HEALTH") {
    checkBackendHealth()
      .then((result) => sendResponse({ success: true, data: result }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }
});

// ------------------------------------------------------------------
// Core: Scan a URL via the backend
// ------------------------------------------------------------------
async function handleScanUrl(url) {
  // Step 1: Check cache first (avoid scanning the same URL repeatedly)
  const cachedResult = await getCachedResult(url);
  if (cachedResult) {
    console.log("[PhishGuard] Cache hit for:", url.substring(0, 60));
    return { ...cachedResult, fromCache: true };
  }

  // Step 2: Call the Express backend
  console.log("[PhishGuard] Scanning URL:", url.substring(0, 60));
  const response = await fetch(`${BACKEND_URL}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });

  if (!response.ok) {
    // Try to parse the error message from the backend
    let errorData;
    try {
      errorData = await response.json();
    } catch {
      errorData = { message: `Backend returned HTTP ${response.status}` };
    }
    throw new Error(errorData.message || `Scan failed (HTTP ${response.status})`);
  }

  const result = await response.json();

  // Step 3: Cache the result
  await cacheResult(url, result);

  // Step 4: Save to history (last 20 scans)
  await addToHistory(url, result);

  return result;
}

// ------------------------------------------------------------------
// Cache helpers (stored in chrome.storage.session — cleared on browser close)
// ------------------------------------------------------------------
async function getCachedResult(url) {
  const key = `cache_${hashUrl(url)}`;
  const stored = await chrome.storage.session.get(key).catch(() => ({}));
  const entry = stored[key];

  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_DURATION_MS) return null;

  return entry.result;
}

async function cacheResult(url, result) {
  const key = `cache_${hashUrl(url)}`;
  await chrome.storage.session
    .set({ [key]: { result, timestamp: Date.now() } })
    .catch(() => {}); // Silently fail — cache is an optimization, not required
}

// Simple hash to use as a storage key (not for security purposes)
function hashUrl(url) {
  let hash = 0;
  for (let i = 0; i < url.length; i++) {
    hash = (hash << 5) - hash + url.charCodeAt(i);
    hash |= 0; // Convert to 32-bit integer
  }
  return Math.abs(hash).toString(36);
}

// ------------------------------------------------------------------
// History helper (stored in chrome.storage.local — persistent)
// ------------------------------------------------------------------
async function addToHistory(url, result) {
  try {
    const stored = await chrome.storage.local.get("scan_history");
    const history = stored.scan_history || [];

    const entry = {
      // Store only the domain, not the full URL, for privacy
      domain: extractDomain(url),
      prediction: result.prediction,
      risk_score: result.risk_score,
      risk_level: result.risk_level,
      scanned_at: result.scanned_at,
    };

    // Add new entry at the front, keep last 20
    history.unshift(entry);
    if (history.length > 20) history.splice(20);

    await chrome.storage.local.set({ scan_history: history });
  } catch {
    // History is optional — silently ignore errors
  }
}

function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url.substring(0, 50);
  }
}

// ------------------------------------------------------------------
// Health check
// ------------------------------------------------------------------
async function checkBackendHealth() {
  const response = await fetch(`${BACKEND_URL}/api/health`, {
    signal: AbortSignal.timeout(5000), // 5 second timeout
  });
  return response.json();
}
