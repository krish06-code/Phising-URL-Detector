"""
evaluate.py
===========
Standalone model evaluation script.

Loads the saved model and evaluates it against a fresh sample of the dataset.
Also runs automated tests to verify the feature schema is consistent.

Usage:
  python ml/evaluate.py

This is useful for:
  - Verifying the model after retraining
  - Checking that inference features match training features
  - Generating a fresh confusion matrix and metrics report
"""

import os
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
)

sys.path.insert(0, os.path.dirname(__file__))
from feature_extractor import FEATURE_NAMES, extract_features, extract_features_as_list

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "phishing_model.pkl")
FEATURE_NAMES_PATH = os.path.join(os.path.dirname(__file__), "models", "feature_names.pkl")
DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "PhiUSIIL_Phishing_URL_Dataset.csv")


# -----------------------------------------------------------------------
# Test 1: Feature schema consistency
# -----------------------------------------------------------------------
def test_feature_schema():
    """
    Verify that FEATURE_NAMES in feature_extractor.py matches what was
    saved with the model. This catches any out-of-sync changes.
    """
    print("Test 1: Feature schema consistency...")

    if not os.path.exists(FEATURE_NAMES_PATH):
        print("  SKIP — model not trained yet")
        return

    saved = joblib.load(FEATURE_NAMES_PATH)
    assert saved == FEATURE_NAMES, (
        f"FAIL: Feature mismatch!\n"
        f"  Saved:    {saved}\n"
        f"  Current:  {FEATURE_NAMES}"
    )
    print("  PASS — feature names match saved model")


# -----------------------------------------------------------------------
# Test 2: Feature extraction on valid URLs
# -----------------------------------------------------------------------
def test_feature_extraction_valid():
    """
    Verify that extract_features returns all expected keys with numeric values.
    """
    print("Test 2: Feature extraction on valid URLs...")

    test_urls = [
        "https://www.google.com",
        "http://evil.xyz/login?a=1&b=2",
        "https://paypal.com.phishing-site.ru/verify",
        "http://192.168.1.1/admin",
    ]

    for url in test_urls:
        features = extract_features(url)

        # Must have all expected keys
        for name in FEATURE_NAMES:
            assert name in features, f"FAIL: Missing feature '{name}' for URL: {url}"

        # All values must be numeric (int or float)
        for name, val in features.items():
            assert isinstance(val, (int, float)), (
                f"FAIL: Feature '{name}' has non-numeric value {type(val)} for URL: {url}"
            )

    print("  PASS — all features extracted with correct types")


# -----------------------------------------------------------------------
# Test 3: Feature extraction on malformed/edge-case URLs
# -----------------------------------------------------------------------
def test_feature_extraction_edge_cases():
    """
    Verify that malformed URLs don't crash the extractor.
    They should return all-zero feature vectors gracefully.
    """
    print("Test 3: Feature extraction on edge-case URLs...")

    edge_cases = [
        "",                    # empty string
        "not-a-url",           # no scheme
        "ftp://weird.scheme",  # non-HTTP scheme
        "javascript:alert(1)", # script injection attempt
        "a" * 10000,           # extremely long string
    ]

    for url in edge_cases:
        try:
            features = extract_features(url)
            # Should return a dict with all expected keys
            assert isinstance(features, dict), f"FAIL: Returned non-dict for: {url[:50]}"
            for name in FEATURE_NAMES:
                assert name in features, f"FAIL: Missing key '{name}' for: {url[:50]}"
        except Exception as e:
            print(f"  FAIL: Exception on URL '{url[:50]}': {e}")
            raise

    print("  PASS — edge-case URLs handled without crashes")


# -----------------------------------------------------------------------
# Test 4: Feature list order matches FEATURE_NAMES
# -----------------------------------------------------------------------
def test_feature_list_order():
    """
    Verify that extract_features_as_list returns values in the same order
    as FEATURE_NAMES. Order matters when passing to the model.
    """
    print("Test 4: Feature list order consistency...")

    url = "https://www.example.com"
    features_dict = extract_features(url)
    features_list = extract_features_as_list(url)

    expected = [features_dict[name] for name in FEATURE_NAMES]
    assert features_list == expected, "FAIL: List order does not match FEATURE_NAMES order"

    print("  PASS — feature list order is consistent")


# -----------------------------------------------------------------------
# Test 5: Model prediction on known examples
# -----------------------------------------------------------------------
def test_model_predictions():
    """
    Basic regression test: verify the loaded model returns sensible predictions.
    We check that model output is in {0, 1} and probabilities sum to ~1.
    """
    print("Test 5: Model prediction output validation...")

    if not os.path.exists(MODEL_PATH):
        print("  SKIP — model not trained yet")
        return

    model = joblib.load(MODEL_PATH)

    test_cases = [
        ("https://www.google.com", "probably legitimate"),
        ("http://192.168.1.1/phishing?user=1", "possibly phishing"),
    ]

    for url, hint in test_cases:
        # IMPORTANT: wrap in a DataFrame with column names so sklearn
        # treats features the same way as during training.
        feature_values = extract_features_as_list(url)
        features_df = pd.DataFrame([feature_values], columns=FEATURE_NAMES)
        pred = model.predict(features_df)[0]
        proba = model.predict_proba(features_df)[0]

        assert pred in [0, 1], f"FAIL: Prediction must be 0 or 1, got {pred}"
        assert abs(sum(proba) - 1.0) < 0.01, "FAIL: Probabilities don't sum to ~1"
        assert all(0.0 <= p <= 1.0 for p in proba), "FAIL: Probabilities out of [0,1] range"

        label_str = "phishing" if pred == 0 else "legitimate"
        print(f"  URL: {url[:50]}")
        print(f"    Prediction: {label_str} (hint: {hint})")
        print(f"    Probabilities: P(phishing)={proba[0]:.3f}, P(legit)={proba[1]:.3f}")

    print("  PASS — model output format is valid")


# -----------------------------------------------------------------------
# Full evaluation on dataset sample
# -----------------------------------------------------------------------
def run_full_evaluation():
    """
    Evaluate the saved model on a random sample of the dataset.
    Reports standard ML metrics and a confusion matrix.

    IMPORTANT: We re-extract features from raw URL strings using
    feature_extractor.py — the same pipeline used at training and inference time.

    Why NOT use df[FEATURE_NAMES] directly from the CSV?
    The dataset's pre-computed columns differ from what our extractor produces:
      - URLLength: dataset includes 'https://' prefix; we strip it (7-8 chars shorter)
      - NoOfLettersInURL: dataset counts over full URL; we count over scheme-stripped URL
      - LetterRatioInURL: ~0.55 in dataset for legit URLs, ~0.86 from our extractor
      - NoOfOtherSpecialCharsInURL: different special-char definition

    Feeding dataset columns to a model trained on extracted features produces
    all-phishing predictions (this was the reported bug). Always re-extract.
    """
    if not os.path.exists(MODEL_PATH):
        print("\nSkipping full evaluation — model not trained yet.")
        return

    print("\nFull model evaluation on dataset sample...")
    print("  (Re-extracting features from raw URLs — this may take ~30s)")
    model = joblib.load(MODEL_PATH)

    # Load a sample (10,000 rows) to keep evaluation fast
    df = pd.read_csv(DATASET_PATH).sample(n=10_000, random_state=42)
    df = df.drop_duplicates(subset=["URL"])

    # ----------------------------------------------------------------
    # FIX: Re-extract features from raw URL strings.
    # DO NOT use df[FEATURE_NAMES] — those are dataset pre-computed columns
    # with a different scale/definition than what our extractor produces.
    # The model was trained on extracted features, so we must match that here.
    # ----------------------------------------------------------------
    from feature_extractor import extract_features_as_list  # noqa: F811
    feature_rows = [extract_features_as_list(url) for url in df["URL"]]
    X = pd.DataFrame(feature_rows, columns=FEATURE_NAMES)
    y = df["label"].reset_index(drop=True)

    y_pred = model.predict(X)
    y_prob = model.predict_proba(X)[:, 1]

    print("\nClassification Report:")
    print(classification_report(y, y_pred, target_names=["Phishing (0)", "Legitimate (1)"]))

    cm = confusion_matrix(y, y_pred)
    print(f"Confusion Matrix:")
    print(f"  TN (correct: legit)  = {cm[0,0]:,}")
    print(f"  FP (false alarm)     = {cm[0,1]:,}")
    print(f"  FN (missed phishing) = {cm[1,0]:,}")
    print(f"  TP (caught phishing) = {cm[1,1]:,}")

    roc = roc_auc_score(y, y_prob)
    pr = average_precision_score(y, y_prob)
    print(f"\nROC-AUC:  {roc:.4f}")
    print(f"PR-AUC:   {pr:.4f}")


def main():
    print("="*60)
    print("PhishGuard — Model Evaluation & Tests")
    print("="*60)

    failures = 0

    for test_fn in [
        test_feature_schema,
        test_feature_extraction_valid,
        test_feature_extraction_edge_cases,
        test_feature_list_order,
        test_model_predictions,
    ]:
        try:
            test_fn()
        except AssertionError as e:
            print(f"  {e}")
            failures += 1
        except Exception as e:
            print(f"  UNEXPECTED ERROR: {e}")
            failures += 1

    print(f"\nTest results: {5 - failures}/5 passed")

    if failures == 0:
        run_full_evaluation()
    else:
        print("\nFix the failing tests before running full evaluation.")

    return failures == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
