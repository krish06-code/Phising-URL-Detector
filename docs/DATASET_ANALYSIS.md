# Dataset Analysis Report

**Dataset:** PhiUSIIL Phishing URL Dataset  
**File:** `PhiUSIIL_Phishing_URL_Dataset.csv`  
**File Size:** ~54 MB  
**Analyzed:** 2026-10-12  

---

## 1. Dataset Overview

| Property | Value |
|---|---|
| **Total rows** | 235,795 |
| **Total columns** | 56 |
| **Legitimate URLs (label=1)** | 134,850 (57.19%) |
| **Phishing URLs (label=0)** | 100,945 (42.81%) |
| **Missing values** | **Zero** — dataset is complete |
| **Exact duplicate rows** | **Zero** |
| **Duplicate URLs** | 425 (0.18%) — will be handled in preprocessing |

> The dataset is mildly class-imbalanced (~57/43 split). This is close enough to balanced
> that we will use stratified train/test splitting rather than oversampling techniques.

---

## 2. Label Encoding

**CONFIRMED by inspection:**
- `label = 1` → **Legitimate** URL (e.g., `https://www.southbankmosaics.com`, URLSimilarityIndex=100)
- `label = 0` → **Phishing** URL (e.g., `http://www.f0519141.xsph.ru`, URLSimilarityIndex=55)
- FILENAME column: phishing files have `mw` prefix (likely "malware" crawl source)

---

## 3. Column Inventory (56 columns)

### Metadata columns — DROPPED before training
| Column | Type | Reason |
|---|---|---|
| `FILENAME` | object | Source file ID — not a URL feature |
| `URL` | object | Raw string — not a numeric feature |
| `Domain` | object | Raw domain string |
| `TLD` | object | TLDLength (numeric) used instead |
| `Title` | object | Match scores used instead |

### Numeric Features (51 columns → 22 selected for inference)

The dataset contains two feature categories:

**URL-lexical features** (computable from URL string alone — USED for inference):
`URLLength`, `DomainLength`, `IsDomainIP`, `TLDLength`, `NoOfSubDomain`,
`HasObfuscation`, `NoOfObfuscatedChar`, `ObfuscationRatio`,
`NoOfLettersInURL`, `LetterRatioInURL`, `NoOfDegitsInURL`, `DegitRatioInURL`,
`NoOfEqualsInURL`, `NoOfQMarkInURL`, `NoOfAmpersandInURL`,
`NoOfOtherSpecialCharsInURL`, `SpacialCharRatioInURL`, `IsHTTPS`

**Page-content features** (require fetching the page — NOT used for real-time inference):
`LineOfCode`, `LargestLineLength`, `HasTitle`, `DomainTitleMatchScore`,
`URLTitleMatchScore`, `HasFavicon`, `Robots`, `IsResponsive`, `NoOfURLRedirect`,
`NoOfSelfRedirect`, `HasDescription`, `NoOfPopup`, `NoOfiFrame`,
`HasExternalFormSubmit`, `HasSocialNet`, `HasSubmitButton`, `HasHiddenFields`,
`HasPasswordField`, `Bank`, `Pay`, `Crypto`, `HasCopyrightInfo`,
`NoOfImage`, `NoOfCSS`, `NoOfJS`, `NoOfSelfRef`, `NoOfEmptyRef`, `NoOfExternalRef`

**Statistical/pre-computed features** (unknown computation pipeline — excluded from inference):
`URLSimilarityIndex`, `CharContinuationRate`, `TLDLegitimateProb`, `URLCharProb`

---

## 4. Data Quality Assessment

| Issue | Finding | Action |
|---|---|---|
| Missing values | None | No imputation needed |
| Duplicate rows | 0 | No action needed |
| Duplicate URLs | 425 (0.18%) | Remove before splitting (prevent leakage) |
| Class imbalance | 57/43 split | Use stratified splitting |
| Outliers | URLLength max=6097 | Tree models are robust — no capping |

---

## 5. Feature Separation by Class

Mean feature values show strong class separation:

| Feature | Phishing (0) | Legitimate (1) |
|---|---|---|
| URLLength | 45.7 | 26.2 |
| DomainLength | 24.5 | 19.2 |
| IsDomainIP | 0.006 | 0.000 |
| NoOfDegitsInURL | 4.3 | 0.05 |
| IsHTTPS | 0.728 (73%) | 0.933 (93%) |
| NoOfOtherSpecialCharsInURL | 3.8 | 1.2 |

Strong separation → tree-based models (Random Forest, XGBoost) expected to perform well.

---

## 6. Inference Strategy Decision

We train on **URL-lexical features only** (18 features) — features computable
from a URL string without fetching the page. This means:
- No network requests to potentially malicious URLs during prediction
- Real-time inference is possible in the Chrome extension
- The model sacrifices some accuracy vs. using all 51 features

**Final feature set for training and inference (18 features):**
```
URLLength, DomainLength, IsDomainIP, TLDLength, NoOfSubDomain,
HasObfuscation, NoOfObfuscatedChar, ObfuscationRatio,
NoOfLettersInURL, LetterRatioInURL, NoOfDegitsInURL, DegitRatioInURL,
NoOfEqualsInURL, NoOfQMarkInURL, NoOfAmpersandInURL,
NoOfOtherSpecialCharsInURL, SpacialCharRatioInURL, IsHTTPS
```

---

## 7. Proposed Training Approach

1. Load dataset, drop metadata + page-content + pre-computed-statistical columns
2. Drop 425 duplicate URLs
3. Stratified split: 70% train / 15% val / 15% test
4. Train: Logistic Regression, Random Forest, XGBoost
5. Select best model by validation F1 and AUC-PR
6. Final evaluation on held-out test set
7. Save model + feature name list with joblib

---

## 8. Limitations

- Excludes page-content features to avoid fetching malicious URLs at inference time
- Model trained on URLs from a specific time period; phishing evolves rapidly
- A URL prediction is not a guarantee of safety or maliciousness
- False negatives (missed phishing) and false positives (flagging safe sites) will occur
