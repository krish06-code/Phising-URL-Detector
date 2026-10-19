"""
live_api_test.py
================
Tests the live ML service endpoint with legitimate and phishing URLs.
Requires the ML service to be running: uvicorn ml-service.app:app --port 8000
"""
import sys
import urllib.request
import urllib.error
import json

ML_URL = "http://localhost:8000/predict"
BACKEND_URL = "http://localhost:3001/api/scan"

test_urls = [
    # --- Legitimate URLs ---
    ("https://www.google.com",       "legitimate"),
    ("https://www.paypal.com",       "legitimate"),
    ("https://www.github.com",       "legitimate"),
    ("https://www.amazon.com",       "legitimate"),
    ("https://www.microsoft.com",    "legitimate"),
    ("https://www.wikipedia.org",    "legitimate"),
    # --- Phishing URLs ---
    ("http://192.168.1.1/login",                              "phishing"),
    ("http://paypal-security-update.evil.com/verify-account", "phishing"),
    ("http://free-iphone-winner.xyz/claim?user=victim",       "phishing"),
    ("https://accounts.google.com-signin.tk/auth",            "phishing"),
    ("http://www.f0519141.xsph.ru",                           "phishing"),
    ("http://bit.ly/2xQtR3p",                                 "phishing"),
]

def post_json(url, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())

def test_service(service_name, endpoint_url, key_map):
    """key_map: maps response field names to prediction/risk_score"""
    print(f"\n{'='*60}")
    print(f"Testing: {service_name}")
    print(f"Endpoint: {endpoint_url}")
    print(f"{'='*60}")

    passed = 0
    failed = 0

    for url, expected in test_urls:
        try:
            result = post_json(endpoint_url, {"url": url})
            prediction = result[key_map["prediction"]]
            risk_score = result[key_map["risk_score"]]

            ok = prediction == expected
            status = "OK" if ok else "WRONG"
            if ok:
                passed += 1
            else:
                failed += 1

            print(f"[{status}] {url[:55]}")
            print(f"       => {prediction} (risk={risk_score:.3f}) | expected={expected}")

        except Exception as e:
            print(f"[ERR] {url[:55]}")
            print(f"       => Error: {e}")
            failed += 1

        print()

    print(f"Result: {passed}/{len(test_urls)} correct ({failed} wrong)")
    return passed, failed


# Test ML service directly
try:
    ml_passed, ml_failed = test_service(
        "ML Service (port 8000)",
        ML_URL,
        {"prediction": "prediction", "risk_score": "risk_score"}
    )
except Exception as e:
    print(f"\nML service not reachable: {e}")
    ml_passed, ml_failed = 0, len(test_urls)

# Test backend (which proxies to ML service)
try:
    be_passed, be_failed = test_service(
        "Backend API (port 3001)",
        BACKEND_URL,
        {"prediction": "prediction", "risk_score": "risk_score"}
    )
except Exception as e:
    print(f"\nBackend not reachable: {e}")
    be_passed, be_failed = 0, len(test_urls)

print(f"\n{'='*60}")
print("SUMMARY")
print(f"{'='*60}")
print(f"ML Service:  {ml_passed}/{len(test_urls)} correct")
print(f"Backend API: {be_passed}/{len(test_urls)} correct")
print()

if ml_failed == 0 and be_failed == 0:
    print("All tests PASSED. The fix is confirmed working end-to-end.")
else:
    print("Some tests FAILED. See above for details.")
    sys.exit(1)
