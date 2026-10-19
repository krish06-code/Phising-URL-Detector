"""
predict.py
==========
Standalone prediction script for testing a URL from the command line.

Usage:
  python ml/predict.py "https://suspicious-site.com/login"
  python ml/predict.py "https://www.google.com"

This script loads the saved model and uses the feature extractor
to make a real prediction. It does NOT hardcode any results.
"""

import sys
import os
import joblib
import pandas as pd

# Add parent directory so we can import feature_extractor
sys.path.insert(0, os.path.dirname(__file__))
from feature_extractor import extract_features, extract_features_as_list, FEATURE_NAMES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "phishing_model.pkl")
FEATURE_NAMES_PATH = os.path.join(os.path.dirname(__file__), "models", "feature_names.pkl")


def load_model():
    """Load the saved model and verify the feature schema."""
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model not found at {MODEL_PATH}. "
            "Please run 'python ml/train.py' first."
        )

    model = joblib.load(MODEL_PATH)
    saved_features = joblib.load(FEATURE_NAMES_PATH)

    if saved_features != FEATURE_NAMES:
        raise ValueError(
            "Feature name mismatch between saved model and feature_extractor.py. "
            "Retrain the model to fix this."
        )

    return model


def predict_url(url: str, model=None) -> dict:
    """
    Predict whether a URL is phishing or legitimate.

    Args:
        url: The URL string to analyze
        model: Optional pre-loaded model (to avoid reloading on every call)

    Returns:
        {
          "prediction": "phishing" or "legitimate",
          "risk_score": float between 0.0 and 1.0,
          "label": 0 (phishing) or 1 (legitimate),
          "features": dict of computed feature values
        }

    risk_score meaning:
        0.0 = model is very confident this is PHISHING
        1.0 = model is very confident this is LEGITIMATE
        ~0.5 = model is uncertain
    """
    if model is None:
        model = load_model()

    # Extract features using the same pipeline as training
    features_dict = extract_features(url)
    feature_values = [features_dict[name] for name in FEATURE_NAMES]

    # Wrap in a named DataFrame — the model was trained with column names
    feature_df = pd.DataFrame([feature_values], columns=FEATURE_NAMES)

    # Get the predicted class (0=phishing, 1=legitimate)
    label = int(model.predict(feature_df)[0])

    # Get the model's confidence
    prob = model.predict_proba(feature_df)[0]
    prob_legitimate = float(prob[1])  # probability of label=1 (legitimate)

    # risk_score: higher = more likely legitimate (0 = phishing, 1 = legit)
    risk_score = round(prob_legitimate, 4)

    prediction_label = "legitimate" if label == 1 else "phishing"

    return {
        "prediction": prediction_label,
        "risk_score": risk_score,
        "label": label,
        "features": features_dict,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ml/predict.py <URL>")
        print('Example: python ml/predict.py "https://suspicious.xyz/login"')
        sys.exit(1)

    url_to_test = sys.argv[1]
    print(f"\nAnalyzing URL: {url_to_test}")
    print("-" * 50)

    try:
        result = predict_url(url_to_test)
        print(f"Prediction:  {result['prediction'].upper()}")
        print(f"Risk Score:  {result['risk_score']:.4f}")
        print(f"  (0.0 = likely phishing, 1.0 = likely legitimate)")
        print(f"\nFeatures used:")
        for k, v in result["features"].items():
            print(f"  {k}: {v}")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)
