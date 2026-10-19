"""
test_predictions.py
===================
Quick test to verify the new model correctly classifies URLs.
"""
import sys
import os
import pandas as pd
_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_ROOT, "ml"))

import joblib
from feature_extractor import extract_features_as_list, FEATURE_NAMES

model = joblib.load(os.path.join(_ROOT, "ml", "models", "phishing_model.pkl"))

test_urls = [
    ("https://www.google.com", "legitimate"),
    ("https://www.paypal.com", "legitimate"),
    ("https://www.github.com", "legitimate"),
    ("https://www.amazon.com", "legitimate"),
    ("https://www.microsoft.com", "legitimate"),
    ("http://192.168.1.1/login", "phishing"),
    ("http://paypal-security-update.evil.com/verify-account", "phishing"),
    ("http://bit.ly/2xQtR3p", "phishing"),
    ("https://accounts.google.com-signin.tk/auth", "phishing"),
    ("http://free-iphone-winner.xyz/claim?user=victim", "phishing"),
    ("http://www.f0519141.xsph.ru", "phishing"),
    ("https://service-mitld.firebaseapp.com/", "phishing"),
]

print("=== Prediction Test ===\n")
correct = 0
for url, expected in test_urls:
    feats = extract_features_as_list(url)
    df = pd.DataFrame([feats], columns=FEATURE_NAMES)
    pred = model.predict(df)[0]
    proba = model.predict_proba(df)[0]
    pred_str = "legitimate" if pred == 1 else "phishing"
    status = "OK" if pred_str == expected else "WRONG"
    correct += 1 if status == "OK" else 0
    print(f"[{status}] {url[:55]}")
    print(f"      => {pred_str} (P_phish={proba[0]:.3f}, P_legit={proba[1]:.3f}) | expected={expected}")
    print()

print(f"Result: {correct}/{len(test_urls)} correct")
