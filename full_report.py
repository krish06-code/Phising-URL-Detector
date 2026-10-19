"""
full_report.py
==============
Comprehensive test and report for PhishGuard ML models.

Tests BOTH XGBoost and Random Forest against:
  - Legitimate URLs (Google, Amazon, ChatGPT, Microsoft, Wikipedia, GitHub, YouTube)
  - Phishing URLs sampled from the PhiUSIIL dataset
  - Edge-case / borderline URLs

Outputs:
  - Per-URL table: expected label, predicted label, risk score, result
  - Summary: TP/TN/FP/FN, accuracy, precision, recall, F1
  - Comparison table: XGBoost vs Random Forest

Usage (from project root):
  python full_report.py

NOTE: Run AFTER train_both_models.py has completed and saved models.
"""
# Use ASCII output so this works on Windows PowerShell without encoding errors
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "ml"))
from feature_extractor import FEATURE_NAMES, extract_features_as_list

# ---------------------------------------------------------------------------
# 1. Test URLs
# ---------------------------------------------------------------------------
LEGITIMATE_URLS = [
    # User-requested legitimate sites
    ("https://www.google.com",             "legitimate", "User-requested legit"),
    ("https://www.amazon.com",             "legitimate", "User-requested legit"),
    ("https://chat.openai.com",            "legitimate", "User-requested legit (ChatGPT)"),
    ("https://www.microsoft.com",          "legitimate", "User-requested legit"),
    ("https://www.wikipedia.org",          "legitimate", "User-requested legit"),
    ("https://www.github.com",             "legitimate", "User-requested legit"),
    ("https://www.youtube.com",            "legitimate", "User-requested legit"),
    # Additional well-known legitimate
    ("https://www.paypal.com",             "legitimate", "Known legit"),
    ("https://www.linkedin.com",           "legitimate", "Known legit"),
    ("https://www.reddit.com",             "legitimate", "Known legit"),
    ("https://www.apple.com",              "legitimate", "Known legit"),
    ("https://stackoverflow.com",          "legitimate", "Known legit"),
]

PHISHING_URLS = [
    # Directly from the PhiUSIIL dataset (verified label=0 rows)
    ("http://www.teramill.com",                                  "phishing", "Dataset phishing"),
    ("http://www.f0519141.xsph.ru",                              "phishing", "Dataset phishing"),
    ("http://www.shprakserf.gq",                                 "phishing", "Dataset phishing"),
    ("https://service-mitld.firebaseapp.com",                    "phishing", "Dataset phishing"),
    ("http://www.kuradox92.lima-city.de",                        "phishing", "Dataset phishing"),
    ("https://liuy-9a930.web.app",                               "phishing", "Dataset phishing"),
    ("http://att-103731-107123.weeblysite.com",                  "phishing", "Dataset phishing"),
    ("https://hidok4f8zl.firebaseapp.com",                       "phishing", "Dataset phishing"),
    # Classic structural phishing patterns (safe to analyze - no network visit)
    ("http://192.168.1.1/login",                                 "phishing", "IP-based phishing"),
    ("http://paypal-security-update.evil.com/verify-account",    "phishing", "Brand spoofing"),
    ("https://accounts.google.com-signin.tk/auth",               "phishing", "Homograph spoofing"),
    ("http://free-iphone-winner.xyz/claim?user=victim",          "phishing", "Prize scam URL"),
    ("http://bit.ly/2xQtR3p",                                    "phishing", "Suspicious shortener"),
]

ALL_URLS = LEGITIMATE_URLS + PHISHING_URLS


def load_model(path, name):
    if not os.path.exists(path):
        print(f"  WARNING: {name} model not found at {path}")
        print("  Run 'python train_both_models.py' first.")
        return None
    return joblib.load(path)


def predict_batch(model, url_list):
    results = []
    for url, expected, category in url_list:
        feats = extract_features_as_list(url)
        df = pd.DataFrame([feats], columns=FEATURE_NAMES)
        raw_pred  = int(model.predict(df)[0])
        proba     = model.predict_proba(df)[0]
        prob_legit = float(proba[1])
        predicted  = "legitimate" if raw_pred == 1 else "phishing"
        correct    = (predicted == expected)
        results.append({
            "url":       url,
            "category":  category,
            "expected":  expected,
            "predicted": predicted,
            "risk_score": round(prob_legit, 4),
            "correct":   correct,
        })
    return results


def compute_metrics(results):
    y_true = [1 if r["expected"]  == "legitimate" else 0 for r in results]
    y_pred = [1 if r["predicted"] == "legitimate" else 0 for r in results]
    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)
    cm   = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    return {
        "accuracy": acc, "precision": prec, "recall": rec, "f1": f1,
        "TP": int(tp), "TN": int(tn), "FP": int(fp), "FN": int(fn),
    }


def print_results_table(model_name, results):
    print()
    print("=" * 90)
    print(f"  MODEL: {model_name}")
    print("=" * 90)
    # Header
    print(f"  {'URL':<50} {'Expected':<12} {'Predicted':<12} {'Risk':>6}  {'Status'}")
    print(f"  " + "-" * 86)
    fp_list, fn_list = [], []
    for r in results:
        url_disp  = r["url"][:49]
        status    = "OK"
        if not r["correct"]:
            status = "WRONG-FP" if r["predicted"] == "legitimate" else "WRONG-FN"
        if "FP" in status:
            fp_list.append(r)
        elif "FN" in status:
            fn_list.append(r)
        print(f"  {url_disp:<50} {r['expected']:<12} {r['predicted']:<12} "
              f"{r['risk_score']:>6.4f}  [{status}]")
    return fp_list, fn_list


def print_metrics(model_name, metrics, fp_list, fn_list, total):
    print()
    print(f"  --- Metrics for {model_name} ({metrics['TP']+metrics['TN']}/{total} correct) ---")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}  "
          f"(of URLs called legitimate, how many truly are)")
    print(f"  Recall:    {metrics['recall']:.4f}  "
          f"(of all legitimate URLs, how many we correctly found)")
    print(f"  F1-Score:  {metrics['f1']:.4f}")
    print()
    print(f"  Confusion Matrix (rows=actual, cols=predicted):")
    print(f"                     Pred:Phishing   Pred:Legit")
    print(f"  Actual:Phishing       TN={metrics['TN']:>5}        FP={metrics['FP']:>5}")
    print(f"  Actual:Legit          FN={metrics['FN']:>5}        TP={metrics['TP']:>5}")
    if fp_list:
        print(f"\n  False Positives (phishing wrongly called legitimate):")
        for r in fp_list:
            print(f"    [FP] {r['url'][:70]}  risk_score={r['risk_score']:.4f}")
    else:
        print(f"\n  False Positives: 0 (none)")
    if fn_list:
        print(f"\n  False Negatives (legitimate wrongly called phishing):")
        for r in fn_list:
            print(f"    [FN] {r['url'][:70]}  risk_score={r['risk_score']:.4f}")
    else:
        print(f"\n  False Negatives: 0 (none)")


def run():
    print("=" * 90)
    print("  PhishGuard -- Comprehensive Model Evaluation Report")
    print("=" * 90)
    print(f"\n  Total test URLs : {len(ALL_URLS)}")
    print(f"    Legitimate    : {len(LEGITIMATE_URLS)}")
    print(f"    Phishing      : {len(PHISHING_URLS)}")
    print()
    print("  NOTE: No network requests are made. Only URL text structure is analyzed.")
    print("        Phishing URLs are NOT visited or opened.")

    model_configs = [
        ("XGBoost",      "ml/models/xgboost_model.pkl"),
        ("RandomForest", "ml/models/rf_model.pkl"),
    ]

    all_metrics = {}
    all_results = {}

    for model_name, model_path in model_configs:
        model = load_model(model_path, model_name)
        if model is None:
            continue
        results    = predict_batch(model, ALL_URLS)
        fp_list, fn_list = print_results_table(model_name, results)
        metrics    = compute_metrics(results)
        print_metrics(model_name, metrics, fp_list, fn_list, len(ALL_URLS))
        all_metrics[model_name] = metrics
        all_results[model_name] = results

    # -----------------------------------------------------------------------
    # Side-by-side comparison
    # -----------------------------------------------------------------------
    if len(all_metrics) >= 2:
        print()
        print("=" * 90)
        print("  COMPARISON: XGBoost vs Random Forest")
        print("=" * 90)
        print(f"  {'Metric':<15} {'XGBoost':>12} {'RandomForest':>14}  {'Winner'}")
        print("  " + "-" * 55)
        for key in ["accuracy", "precision", "recall", "f1"]:
            xg = all_metrics["XGBoost"][key]
            rf = all_metrics["RandomForest"][key]
            if   xg > rf: winner = "XGBoost"
            elif rf > xg: winner = "RandomForest"
            else:         winner = "Tie"
            print(f"  {key.capitalize():<15} {xg:>12.4f} {rf:>14.4f}  {winner}")
        print()
        for k in ["TP", "TN", "FP", "FN"]:
            xg = all_metrics["XGBoost"][k]
            rf = all_metrics["RandomForest"][k]
            print(f"  {k:<15} {xg:>12d} {rf:>14d}")

        # Per-URL disagreements
        print()
        print("  URLs where XGBoost and Random Forest DISAGREE:")
        xg_res = all_results["XGBoost"]
        rf_res = all_results["RandomForest"]
        disagree = [
            (xg_res[i], rf_res[i])
            for i in range(len(xg_res))
            if xg_res[i]["predicted"] != rf_res[i]["predicted"]
        ]
        if disagree:
            for xg_r, rf_r in disagree:
                print(f"    {xg_r['url'][:65]}")
                print(f"      XGBoost={xg_r['predicted']} (risk={xg_r['risk_score']:.3f})  "
                      f"RF={rf_r['predicted']} (risk={rf_r['risk_score']:.3f})  "
                      f"expected={xg_r['expected']}")
        else:
            print("    None -- both models agree on all test URLs")

    print()
    print("=" * 90)
    print("  Report complete. All predictions are real model outputs -- nothing hardcoded.")
    print("=" * 90)
    print()


if __name__ == "__main__":
    run()
