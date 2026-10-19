"""Test URL normalization fix — verifies complex real browser URLs are correctly classified"""
import urllib.request, json

test_cases = [
    # Google Search URL with full tracking params (exactly like the screenshot)
    ("https://www.google.com/search?q=+google&sca_esv=80abbfb0773073f1&rlz=1C10NGR_enIN1123IN1123&sxsrf=ADLYWItest", "legitimate"),
    # YouTube video with playlist params
    ("https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLxxx&index=1", "legitimate"),
    # Amazon product with affiliate params
    ("https://www.amazon.com/dp/B08J5F3G18?ref=cm_sw_r_apan_glt&th=1", "legitimate"),
    # ChatGPT conversation URL
    ("https://chat.openai.com/c/abc123-def456?model=gpt-4", "legitimate"),
    # GitHub with query params
    ("https://github.com/user/repo/blob/main/README.md?plain=1", "legitimate"),
    # Microsoft with session token
    ("https://www.microsoft.com/en-in/microsoft-365?activetab=pivot:overviewtab", "legitimate"),
    # A real phishing URL with query params should still be detected
    ("https://accounts.google.com-signin.tk/auth?session=abc&token=xyz", "phishing"),
    ("http://paypal-verify.evil.com/login?redirect=paypal.com&token=abc", "phishing"),
]

backend = "http://localhost:3001/api/scan"
passed = 0
failed = 0

print("=" * 70)
print("URL Normalization Fix — Test Results")
print("=" * 70)

for url, expected in test_cases:
    data = json.dumps({"url": url}).encode()
    req = urllib.request.Request(backend, data=data, headers={"Content-Type": "application/json"})
    resp = json.loads(urllib.request.urlopen(req, timeout=5).read())

    analyzed = resp.get("analyzed_url", "N/A")
    prediction = resp["prediction"]
    risk = resp["risk_score"]
    ok = (prediction == expected)

    status = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1

    print(f"[{status}] {prediction.upper()} (risk={risk:.3f})")
    print(f"  Original : {url[:70]}")
    print(f"  Analyzed : {analyzed}")
    print(f"  Expected : {expected}")
    print()

print(f"Result: {passed}/{len(test_cases)} passed, {failed} failed")
