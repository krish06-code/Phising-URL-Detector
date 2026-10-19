"""
train_both_models.py
====================
Trains BOTH XGBoost and Random Forest on the dataset using re-extracted URL
features, evaluates both, and saves each to its own .pkl file.

This does NOT replace the main model (phishing_model.pkl) — it adds:
  ml/models/xgboost_model.pkl
  ml/models/rf_model.pkl

Usage (from project root):
  python train_both_models.py

Takes ~3-5 minutes due to feature extraction from 235k URLs.
"""

import os
import sys
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
    classification_report,
)
from xgboost import XGBClassifier

_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_ROOT, "ml"))
from feature_extractor import FEATURE_NAMES, extract_features_as_list

DATASET_PATH = os.path.join(_ROOT, "PhiUSIIL_Phishing_URL_Dataset.csv")
MODEL_DIR = os.path.join(_ROOT, "ml", "models")
RANDOM_STATE = 42

# -----------------------------------------------------------------------
# Step 1: Load dataset and re-extract features from raw URLs
# -----------------------------------------------------------------------
print("=" * 60)
print("PhishGuard — Training XGBoost + Random Forest")
print("=" * 60)

print("\nStep 1: Loading dataset...")
df = pd.read_csv(DATASET_PATH)
df = df.drop_duplicates(subset=["URL"], keep="first")
print(f"  Rows after dedup: {len(df):,}")

label_counts = df["label"].value_counts()
print(f"  label=0 (phishing):   {label_counts.get(0, 0):,}")
print(f"  label=1 (legitimate): {label_counts.get(1, 0):,}")

print(f"\nStep 2: Re-extracting features from {len(df):,} URLs...")
print("  (This takes ~3-5 minutes — please wait)")
start = time.time()

feature_rows = []
urls = df["URL"].tolist()
n = len(urls)
for i, url in enumerate(urls):
    feature_rows.append(extract_features_as_list(url))
    if (i + 1) % 30000 == 0:
        elapsed = time.time() - start
        pct = (i + 1) / n * 100
        print(f"  Progress: {i+1:,}/{n:,} ({pct:.0f}%) — {elapsed:.0f}s")

elapsed = time.time() - start
print(f"  Done in {elapsed:.1f}s")

X = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)
y = df["label"].reset_index(drop=True)

# -----------------------------------------------------------------------
# Step 3: Train/test split
# -----------------------------------------------------------------------
print("\nStep 3: Splitting data (80% train, 20% test)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=RANDOM_STATE, stratify=y
)
print(f"  Train: {len(X_train):,}  |  Test: {len(X_test):,}")

# -----------------------------------------------------------------------
# Step 4: Train both models
# -----------------------------------------------------------------------
models_config = {
    "XGBoost": XGBClassifier(
        n_estimators=300,
        max_depth=7,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        eval_metric="logloss",
        verbosity=0,
    ),
    "RandomForest": RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_leaf=5,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        class_weight="balanced",
    ),
}

results = {}
for model_name, clf in models_config.items():
    print(f"\n{'='*60}")
    print(f"Step 4: Training {model_name}...")
    t0 = time.time()
    clf.fit(X_train, y_train)
    train_time = time.time() - t0
    print(f"  Training time: {train_time:.1f}s")

    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)
    roc  = roc_auc_score(y_test, y_prob)
    cm   = confusion_matrix(y_test, y_pred)

    results[model_name] = {
        "model": clf,
        "accuracy": acc, "precision": prec, "recall": rec,
        "f1": f1, "roc_auc": roc, "cm": cm,
    }

    print(f"\n  Test-set metrics for {model_name}:")
    print(f"    Accuracy:  {acc:.4f}")
    print(f"    Precision: {prec:.4f}")
    print(f"    Recall:    {rec:.4f}")
    print(f"    F1-Score:  {f1:.4f}")
    print(f"    ROC-AUC:   {roc:.4f}")
    print(f"    Confusion Matrix:")
    print(f"      TN={cm[0,0]:,}  FP={cm[0,1]:,}")
    print(f"      FN={cm[1,0]:,}  TP={cm[1,1]:,}")
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred,
          target_names=["Phishing (0)", "Legitimate (1)"],
          zero_division=0))

# -----------------------------------------------------------------------
# Step 5: Save both models
# -----------------------------------------------------------------------
print(f"\n{'='*60}")
print("Step 5: Saving models...")
os.makedirs(MODEL_DIR, exist_ok=True)

save_paths = {
    "XGBoost":      os.path.join(MODEL_DIR, "xgboost_model.pkl"),
    "RandomForest": os.path.join(MODEL_DIR, "rf_model.pkl"),
}
for model_name, path in save_paths.items():
    joblib.dump(results[model_name]["model"], path)
    print(f"  Saved {model_name} -> {path}")

# Save feature names alongside
joblib.dump(FEATURE_NAMES, os.path.join(MODEL_DIR, "feature_names.pkl"))
print(f"  Feature names saved -> {os.path.join(MODEL_DIR, 'feature_names.pkl')}")

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
print(f"\n{'='*60}")
print("FINAL SUMMARY")
print("="*60)
for name, r in results.items():
    print(f"  {name:15s}: Acc={r['accuracy']:.4f}  F1={r['f1']:.4f}  ROC-AUC={r['roc_auc']:.4f}")

best_name = max(results, key=lambda k: results[k]["f1"])
print(f"\n  Best model by F1: {best_name}")
print("\nDone! Both models are saved and ready for testing.")
