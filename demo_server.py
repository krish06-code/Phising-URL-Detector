"""
demo_server.py
==============
Serves the phishing demo page at a suspicious-looking URL so PhishGuard
can detect it during live demonstration.

URL it runs on:  http://paypal-secure-verify.local-login.com:9999
(This is just localhost:9999, but the Host header makes it look phishing)

Usage:
  python demo_server.py

Then open Chrome and go to:
  http://localhost:9999
"""
import http.server
import socketserver
import os

PORT = 9999
DEMO_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo")

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DEMO_DIR, **kwargs)

    def do_GET(self):
        # Always serve phishing_demo.html for any path
        self.path = "/phishing_demo.html"
        return super().do_GET()

    def log_message(self, format, *args):
        print(f"[Demo Server] {format % args}")

print("=" * 55)
print("  PhishGuard — Phishing Demo Server")
print("=" * 55)
print(f"  Open Chrome and visit:")
print(f"  http://localhost:{PORT}")
print(f"")
print(f"  The extension will analyze the URL. Since localhost")
print(f"  has no www. and uses http://, it may flag as phishing.")
print(f"  Press Ctrl+C to stop the server.")
print("=" * 55)

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    httpd.serve_forever()
