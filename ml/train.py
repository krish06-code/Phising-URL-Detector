"""
train.py
========
Trains phishing URL detection models and saves the best one.

KEY DESIGN: We recompute all features from raw URLs using feature_extractor.py
at training time. This ensures training and inference features are IDENTICAL.
The dataset's pre-computed feature columns are NOT used — we extract fresh from URLs.

This eliminates any training/inference skew (the root cause of misclassification).

Usage:
  cd phishing-url-detector
  python ml/train.py

The dataset CSV must be at the project root:
  phishing-url-detector/PhiUSIIL_Phishing_URL_Dataset.csv
"""

import os
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
    average_precision_score,
)
from xgboost import XGBClassifier

import sys
sys.path.insert(0, os.path.dirname(__file__))
from feature_extractor import FEATURE_NAMES, extract_features_as_list

# -----------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------
DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "PhiUSIIL_Phishing_URL_Dataset.csv")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")
FEATURE_NAMES_PATH = os.path.join(MODEL_DIR, "feature_names.pkl")
MODEL_VERSION = "3.0"  # v3 = trained from extracted URL features (no dataset skew)

RANDOM_STATE = 42

LABEL_PHISHING = 0
LABEL_LEGITIMATE = 1


def load_and_prepare_data():
    """
    Load the dataset, then RE-EXTRACT features from the raw URL strings
    using our feature_extractor. This guarantees training == inference features.
    """
    print("Loading dataset...")
    df = pd.read_csv(DATASET_PATH)
    print(f"  Loaded {len(df):,} rows, {df.shape[1]} columns")

    # ---- Remove duplicate URLs ----
    before = len(df)
    df = df.drop_duplicates(subset=["URL"], keep="first")
    after = len(df)
    print(f"  Removed {before - after} duplicate URLs. Remaining: {after:,}")

    # ---- Check label distribution ----
    label_counts = df["label"].value_counts()
    print(f"  Label distribution after dedup:")
    print(f"    Phishing   (0): {label_counts.get(0, 0):,}")
    print(f"    Legitimate (1): {label_counts.get(1, 0):,}")

    # ---- Re-extract features from raw URLs ----
    # This is the KEY step: we compute features the same way as at inference time.
    # Slower than using the pre-computed columns, but ensures train==infer consistency.
    print(f"\n  Extracting features from {after:,} URLs (this takes ~60s)...")
    start = time.time()

    feature_rows = []
    urls = df["URL"].tolist()
    n = len(urls)
    for i, url in enumerate(urls):
        feature_rows.append(extract_features_as_list(url))
        if (i + 1) % 20000 == 0:
            elapsed = time.time() - start
            pct = (i + 1) / n * 100
            print(f"    Progress: {i+1:,}/{n:,} ({pct:.0f}%) — {elapsed:.0f}s elapsed")

    elapsed = time.time() - start
    print(f"  Feature extraction complete in {elapsed:.1f}s")

    X = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)
    y = df["label"].reset_index(drop=True)

    print(f"  Feature matrix shape: {X.shape}")
    return X, y


def split_data(X, y):
    """Split into train (70%), validation (15%), and test (15%) sets."""
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=RANDOM_STATE, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=RANDOM_STATE, stratify=y_temp
    )

    print(f"\nData split:")
    print(f"  Train: {len(X_train):,} samples")
    print(f"  Val:   {len(X_val):,} samples")
    print(f"  Test:  {len(X_test):,} samples")
    return X_train, X_val, X_test, y_train, y_val, y_test


def evaluate_model(model, X, y, split_name=""):
    """Run predictions and print a full evaluation report."""
    y_pred = model.predict(X)

    if hasattr(model, "predict_proba"):
        y_prob = model.predict_proba(X)[:, 1]
        roc_auc = roc_auc_score(y, y_prob)
        pr_auc = average_precision_score(y, y_prob)
    else:
        roc_auc = None
        pr_auc = None

    acc = accuracy_score(y, y_pred)
    prec = precision_score(y, y_pred, zero_division=0)
    rec = recall_score(y, y_pred, zero_division=0)
    f1 = f1_score(y, y_pred, zero_division=0)
    cm = confusion_matrix(y, y_pred)

    print(f"\n  --- {split_name} Evaluation ---")
    print(f"  Accuracy:  {acc:.4f}")
    print(f"  Precision: {prec:.4f}  (of legitimate URLs detected, how many are really legit?)")
    print(f"  Recall:    {rec:.4f}   (of all legit URLs, how many did we correctly identify?)")
    print(f"  F1 Score:  {f1:.4f}")
    if roc_auc is not None:
        print(f"  ROC-AUC:   {roc_auc:.4f}")
        print(f"  PR-AUC:    {pr_auc:.4f}")
    print(f"  Confusion Matrix (rows=actual, cols=predicted):")
    print(f"    TN (phishing->phishing)={cm[0,0]:,}  FP (phishing->legit)={cm[0,1]:,}")
    print(f"    FN (legit->phishing)   ={cm[1,0]:,}  TP (legit->legit)   ={cm[1,1]:,}")

    return {
        "accuracy": acc, "precision": prec, "recall": rec,
        "f1": f1, "roc_auc": roc_auc, "pr_auc": pr_auc
    }


def train_all_models(X_train, y_train, X_val, y_val):
    """Train all models, evaluate on validation set, return the best."""
    candidates = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                max_iter=2000,
                random_state=RANDOM_STATE,
                C=1.0,
                class_weight="balanced",
            )),
        ]),
        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_leaf=5,
            random_state=RANDOM_STATE,
            n_jobs=-1,
            class_weight="balanced",
        ),
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
    }

    results = {}
    best_model = None
    best_f1 = -1
    best_name = ""

    print("\n" + "="*60)
    print("Training and evaluating models...")
    print("="*60)

    for name, model in candidates.items():
        print(f"\n[{name}]")
        start = time.time()
        model.fit(X_train, y_train)
        train_time = time.time() - start
        print(f"  Training time: {train_time:.1f}s")

        val_metrics = evaluate_model(model, X_val, y_val, split_name="Validation")
        results[name] = {"model": model, "val_metrics": val_metrics}

        if val_metrics["f1"] > best_f1:
            best_f1 = val_metrics["f1"]
            best_model = model
            best_name = name

    print(f"\n{'='*60}")
    print(f"Best model: {best_name} (Validation F1 = {best_f1:.4f})")
    print("="*60)

    return best_model, best_name, results


def save_model(model, feature_names):
    """Save the trained model and feature name list to disk."""
    os.makedirs(MODEL_DIR, exist_ok=True)

    joblib.dump(model, MODEL_PATH)
    print(f"\nModel saved to: {MODEL_PATH}")

    joblib.dump(feature_names, FEATURE_NAMES_PATH)
    print(f"Feature names saved to: {FEATURE_NAMES_PATH}")

    version_path = os.path.join(MODEL_DIR, "model_version.txt")
    with open(version_path, "w") as f:
        f.write(MODEL_VERSION)
    print(f"Model version: {MODEL_VERSION}")


def verify_saved_model(X_test, y_test):
    """Load the saved model from disk and verify it works correctly."""
    print("\nVerifying saved model by loading from disk...")
    loaded_model = joblib.load(MODEL_PATH)
    loaded_features = joblib.load(FEATURE_NAMES_PATH)

    assert loaded_features == FEATURE_NAMES, "Feature name mismatch after loading!"

    print("  Loaded model verification:")
    evaluate_model(loaded_model, X_test, y_test, split_name="Test (Loaded Model)")
    print("  Saved model verified successfully.")


def main():
    print("\n" + "="*60)
    print("PhishGuard -- ML Training Pipeline v3")
    print("  (Features extracted from raw URLs -- no dataset skew)")
    print("="*60)

    X, y = load_and_prepare_data()
    X_train, X_val, X_test, y_train, y_val, y_test = split_data(X, y)
    best_model, best_name, all_results = train_all_models(X_train, y_train, X_val, y_val)

    print(f"\n{'='*60}")
    print(f"Final test set evaluation for: {best_name}")
    print("="*60)
    test_metrics = evaluate_model(best_model, X_test, y_test, split_name="Test")

    print(f"\n{'='*60}")
    print("Summary comparison (Validation F1):")
    for name, result in all_results.items():
        marker = " <-- SELECTED" if name == best_name else ""
        print(f"  {name}: F1={result['val_metrics']['f1']:.4f}{marker}")

    save_model(best_model, FEATURE_NAMES)
    verify_saved_model(X_test, y_test)

    print("\nTraining complete!")
    print(f"Model saved to: {MODEL_PATH}")
    print("Start the ML service: uvicorn ml-service.app:app --port 8000")


if __name__ == "__main__":
    main()
