"""
compare_features.py
===================
Compare dataset columns vs re-extracted features for same URLs.
This identifies the root cause of misclassification.
"""
import sys, joblib, pandas as pd, numpy as np
sys.path.insert(0, 'ml')
from feature_extractor import FEATURE_NAMES, extract_features_as_list

model = joblib.load('ml/models/phishing_model.pkl')
df = pd.read_csv('PhiUSIIL_Phishing_URL_Dataset.csv').sample(n=10, random_state=42)

print('=== Dataset column values vs re-extracted features ===')
print()

for _, row in df.iterrows():
    url = row['URL']
    # From dataset CSV columns
    dataset_feats = [row[f] for f in FEATURE_NAMES]
    # Re-extracted from the URL string
    extracted_feats = extract_features_as_list(url)
    
    print(f'URL: {url[:70]}')
    print(f'  True label: {row["label"]} (1=legit, 0=phishing)')

    # Show key differences
    for i, fname in enumerate(FEATURE_NAMES):
        d_val = dataset_feats[i]
        e_val = extracted_feats[i]
        if abs(float(d_val) - float(e_val)) > 0.01:
            print(f'  MISMATCH {fname}: dataset={d_val}, extracted={e_val}')

    # Predict using dataset columns
    df_dataset = pd.DataFrame([dataset_feats], columns=FEATURE_NAMES)
    pred_dataset = model.predict(df_dataset)[0]
    prob_dataset = model.predict_proba(df_dataset)[0]

    # Predict using re-extracted features
    df_extracted = pd.DataFrame([extracted_feats], columns=FEATURE_NAMES)
    pred_extracted = model.predict(df_extracted)[0]
    prob_extracted = model.predict_proba(df_extracted)[0]

    label_d = 'legitimate' if pred_dataset == 1 else 'phishing'
    label_e = 'legitimate' if pred_extracted == 1 else 'phishing'
    print(f'  Using DATASET cols: {label_d} (P_legit={prob_dataset[1]:.3f})')
    print(f'  Using EXTRACTED:    {label_e} (P_legit={prob_extracted[1]:.3f})')
    print()

print()
print('=== Scale comparison (mean values) ===')
# Compare mean feature values from dataset vs extracted
legit_df = df[df['label'] == 1].head(50)
for fname in ['URLLength', 'DomainLength', 'NoOfLettersInURL', 'LetterRatioInURL']:
    dataset_val = legit_df[fname].mean() if fname in legit_df.columns else 'N/A'
    extracted_vals = [extract_features_as_list(u)[FEATURE_NAMES.index(fname)] for u in legit_df['URL'].tolist()]
    extracted_val = sum(extracted_vals)/len(extracted_vals) if extracted_vals else 'N/A'
    print(f'{fname}: dataset_mean={dataset_val:.2f}, extracted_mean={extracted_val:.2f}')
