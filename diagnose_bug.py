"""
diagnose_bug.py
===============
Deep diagnostic to find the exact root cause of the
'classifies everything as phishing' bug.
"""
import sys, joblib, pandas as pd, numpy as np

sys.path.insert(0, 'ml')
from feature_extractor import extract_features_as_list, extract_features, FEATURE_NAMES

# -----------------------------------------------------------------------
# 1. Feature extraction for known URLs
# -----------------------------------------------------------------------
print("=" * 60)
print("1. FEATURE EXTRACTION CHECK")
print("=" * 60)

test_urls = [
    "https://www.google.com",
    "https://www.paypal.com",
    "http://paypal-security-update.evil.com/verify-account",
    "http://192.168.1.1/login",
]

for url in test_urls:
    feats = extract_features(url)
    print(f"\nURL: {url}")
    for k, v in feats.items():
        print(f"  {k}: {v}")

# -----------------------------------------------------------------------
# 2. Model internals
# -----------------------------------------------------------------------
print("\n" + "=" * 60)
print("2. MODEL INTERNALS")
print("=" * 60)

model = joblib.load('ml/models/phishing_model.pkl')
print(f"Model type: {type(model).__name__}")
print(f"Model version: {open('ml/models/model_version.txt').read().strip()}")

if hasattr(model, 'classes_'):
    print(f"classes_: {model.classes_}")
    print(f"  class 0 = {model.classes_[0]}, class 1 = {model.classes_[1]}")

# -----------------------------------------------------------------------
# 3. Raw predictions
# -----------------------------------------------------------------------
print("\n" + "=" * 60)
print("3. RAW PREDICTIONS (no interpretation layer)")
print("=" * 60)

for url in test_urls:
    feats = extract_features_as_list(url)
    df = pd.DataFrame([feats], columns=FEATURE_NAMES)
    raw_pred = model.predict(df)[0]
    proba = model.predict_proba(df)[0]
    print(f"\nURL: {url[:60]}")
    print(f"  model.predict() raw = {raw_pred}  (dtype={type(raw_pred).__name__})")
    print(f"  proba[0]={proba[0]:.4f}  proba[1]={proba[1]:.4f}")
    # Interpret using the train.py constants
    LABEL_PHISHING = 0
    LABEL_LEGITIMATE = 1
    interpretation = "legitimate" if int(raw_pred) == LABEL_LEGITIMATE else "phishing"
    print(f"  => {interpretation}")

# -----------------------------------------------------------------------
# 4. Check if there's a label inversion issue in training data
# -----------------------------------------------------------------------
print("\n" + "=" * 60)
print("4. DATASET LABEL SANITY CHECK")
print("=" * 60)

df_data = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv", nrows=20)
print("Label counts in first 20 rows:")
print(df_data['label'].value_counts())
print("\nSample rows showing URL + label + IsHTTPS:")
sample = df_data[['URL', 'label', 'IsHTTPS', 'IsDomainIP', 'URLLength']].head(10)
print(sample.to_string())

# -----------------------------------------------------------------------
# 5. Check model training data assumptions vs dataset
# -----------------------------------------------------------------------
print("\n" + "=" * 60)
print("5. DATASET LABEL MEANING VERIFICATION")
print("=" * 60)

df_full = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv", nrows=5000)
label0 = df_full[df_full['label'] == 0]
label1 = df_full[df_full['label'] == 1]

print(f"label=0 count: {len(label0)}, label=1 count: {len(label1)}")
print(f"\nlabel=0 IsHTTPS mean: {label0['IsHTTPS'].mean():.3f}")
print(f"label=1 IsHTTPS mean: {label1['IsHTTPS'].mean():.3f}")
print(f"\nlabel=0 sample URLs (first 5):")
for _, row in label0[['URL', 'label', 'IsHTTPS']].head(5).iterrows():
    print(f"  [{row['label']}] {row['URL']}")
print(f"\nlabel=1 sample URLs (first 5):")
for _, row in label1[['URL', 'label', 'IsHTTPS']].head(5).iterrows():
    print(f"  [{row['label']}] {row['URL']}")

# Also check the URLSimilarityIndex (100 = legitimate in this dataset)
if 'URLSimilarityIndex' in df_full.columns:
    print(f"\nlabel=0 URLSimilarityIndex mean: {label0['URLSimilarityIndex'].mean():.2f}")
    print(f"label=1 URLSimilarityIndex mean: {label1['URLSimilarityIndex'].mean():.2f}")
    print("(100 = URL matches a legitimate known site)")

print("\nDone. Diagnose complete.")
