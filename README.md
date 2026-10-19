# PhishGuard — AI-Powered Phishing URL Detector

<div align="center">

![PhishGuard Banner](docs/banner.png)

**A full-stack machine learning system that detects phishing URLs in real time.**  
Chrome extension · FastAPI ML service · Node.js/Express backend · XGBoost + Random Forest

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)](https://python.org)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green?logo=node.js)](https://nodejs.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Accuracy](https://img.shields.io/badge/Model%20Accuracy-96.8%25-brightgreen)]()

</div>

---

## What It Does

PhishGuard analyzes the structure of a URL and uses a machine learning model to decide whether it is **phishing** or **legitimate** — without ever visiting the page. It works as a Chrome browser extension that shows a warning whenever you land on a suspicious site.

| Legitimate Site | Phishing Site |
|---|---|
| ![Safe](https://img.shields.io/badge/✓-Looks%20Legitimate-brightgreen) | ![Phishing](https://img.shields.io/badge/⚠-Phishing%20Detected-red) |
| `https://www.google.com` | `http://paypal-security-update.evil.com` |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Chrome Extension                    │
│  popup.html · popup.js · background.js (service     │
│  worker) — captures current tab URL, sends to       │
│  backend, displays result                           │
└──────────────────────┬──────────────────────────────┘
                       │ POST /api/scan
┌──────────────────────▼──────────────────────────────┐
│           Node.js / Express Backend (port 3001)      │
│  Validates URL, normalizes it (strips query params), │
│  rate limits, forwards to ML service                │
└──────────────────────┬──────────────────────────────┘
                       │ POST /predict
┌──────────────────────▼──────────────────────────────┐
│         Python / FastAPI ML Service (port 8000)      │
│  Extracts 18 URL features, runs XGBoost model,      │
│  returns prediction + risk score                    │
└─────────────────────────────────────────────────────┘
```

---

## Model Performance

Trained on the **PhiUSIIL Phishing URL Dataset** (235,370 URLs).

| Metric | XGBoost | Random Forest |
|---|---|---|
| **Accuracy** | **96.8%** | 96.8% |
| **Precision** | 95.8% | 95.9% |
| **Recall** | 98.8% | 98.6% |
| **F1-Score** | **97.3%** | 97.2% |
| **ROC-AUC** | **98.8%** | 98.8% |

### Live URL Predictions (Verified — No Hardcoding)

| URL | Prediction | Risk Score |
|---|---|---|
| `https://www.google.com` | ✅ Legitimate | 0.988 |
| `https://www.youtube.com` | ✅ Legitimate | 0.988 |
| `https://chat.openai.com` | ✅ Legitimate | 0.988 |
| `https://www.amazon.com` | ✅ Legitimate | 0.987 |
| `https://www.github.com` | ✅ Legitimate | 0.987 |
| `https://www.microsoft.com` | ✅ Legitimate | 0.981 |
| `http://192.168.1.1/login` | 🔴 Phishing | 0.000 |
| `http://paypal-security-update.evil.com` | 🔴 Phishing | 0.000 |
| `https://accounts.google.com-signin.tk` | 🔴 Phishing | 0.046 |
| `http://free-iphone-winner.xyz` | 🔴 Phishing | 0.000 |

---

## Features Extracted (18 URL Features)

The model uses only the URL text — it never fetches page content.

| Feature | Description |
|---|---|
| `URLLength` | Total length of the URL |
| `DomainLength` | Length of the domain part |
| `IsDomainIP` | 1 if the domain is an IP address |
| `TLDLength` | Length of the top-level domain |
| `NoOfSubDomain` | Number of subdomains |
| `HasObfuscation` | 1 if URL contains `@`, `%20`, etc. |
| `NoOfObfuscatedChar` | Count of obfuscated characters |
| `ObfuscationRatio` | Ratio of obfuscated chars to total |
| `NoOfLettersInURL` | Total letter count |
| `LetterRatioInURL` | Ratio of letters to total characters |
| `NoOfDegitsInURL` | Total digit count |
| `DegitRatioInURL` | Ratio of digits to total characters |
| `NoOfEqualsInURL` | Count of `=` signs |
| `NoOfQMarkInURL` | Count of `?` marks |
| `NoOfAmpersandInURL` | Count of `&` signs |
| `NoOfOtherSpecialCharsInURL` | Count of other special characters |
| `SpacialCharRatioInURL` | Ratio of special chars to total |
| `IsHTTPS` | 1 if scheme is HTTPS |

---

## Project Structure

```
phishing-url-detector/
│
├── ml/                          # Machine Learning pipeline
│   ├── feature_extractor.py     # URL feature extraction (18 features)
│   ├── train.py                 # Model training script
│   ├── evaluate.py              # Model evaluation + unit tests
│   ├── predict.py               # CLI prediction tool
│   └── models/                  # Saved trained models
│       ├── phishing_model.pkl   # Main XGBoost model
│       ├── xgboost_model.pkl    # XGBoost (standalone)
│       ├── rf_model.pkl         # Random Forest (standalone)
│       └── feature_names.pkl    # Feature schema
│
├── ml-service/                  # FastAPI inference server
│   ├── app.py                   # REST API (port 8000)
│   └── requirements.txt
│
├── backend/                     # Node.js/Express API
│   ├── server.js                # Server entry point (port 3001)
│   ├── app.js                   # Express app configuration
│   ├── controllers/
│   │   └── scanController.js    # URL scan + health endpoints
│   ├── services/
│   │   └── mlService.js         # Communicates with ML service
│   ├── middleware/
│   │   ├── rateLimiter.js       # Rate limiting
│   │   └── errorHandler.js      # Centralized error handling
│   ├── routes/
│   │   └── scanRoutes.js        # API route definitions
│   ├── utils/
│   │   └── validators.js        # URL validation
│   ├── tests/
│   │   └── backend.test.js      # Integration tests (14 tests)
│   └── package.json
│
├── extension/                   # Chrome Extension (Manifest V3)
│   ├── manifest.json            # Extension configuration
│   ├── popup.html               # Extension popup UI
│   ├── popup.js                 # Popup logic
│   ├── popup.css                # Styling
│   ├── background.js            # Service worker
│   └── icons/                   # Extension icons
│
├── demo/                        # Teacher/demo materials
│   └── phishing_demo.html       # Fake phishing page (demo only)
│
├── full_report.py               # Full model comparison report
├── train_both_models.py         # Train XGBoost + Random Forest
├── live_api_test.py             # End-to-end API tests
├── test_predictions.py          # Quick URL prediction test
├── test_normalization.py        # URL normalization tests
├── demo_server.py               # Local demo server
├── start_phishguard.bat         # Windows one-click startup
└── README.md
```

---

## Prerequisites

| Tool | Minimum Version | Check |
|---|---|---|
| Python | 3.10+ | `python --version` |
| Node.js | 18+ | `node --version` |
| npm | 9+ | `npm --version` |
| Git | any | `git --version` |

---

## Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/phishing-url-detector.git
cd phishing-url-detector
```

### 2. Download the dataset

Download the **PhiUSIIL Phishing URL Dataset** from Kaggle:
[https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls](https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls)

Place the file in the project root:
```
phishing-url-detector/
└── PhiUSIIL_Phishing_URL_Dataset.csv   ← here
```

> The dataset is not included in the repository (54 MB, excluded by `.gitignore`).

### 3. Create Python virtual environment

```bash
python -m venv venv
```

### 4. Install Python dependencies

```bash
# Training dependencies
venv\Scripts\pip install -r ml\requirements.txt

# Inference service dependencies
venv\Scripts\pip install -r ml-service\requirements.txt
```

### 5. Train the model

```bash
venv\Scripts\python.exe ml\train.py
```

This creates `ml/models/phishing_model.pkl` (~1 MB). Takes about 1–2 minutes.

To train and compare both XGBoost and Random Forest:
```bash
venv\Scripts\python.exe train_both_models.py
```

### 6. Install Node.js dependencies

```bash
cd backend
npm install
cd ..
```

---

## Running the Project

### Option A — Double-click (Windows, easiest)
```
Double-click: start_phishguard.bat
```

### Option B — Manual (two terminal windows)

**Terminal 1 — ML Service:**
```bash
cd phishing-url-detector
.\venv\Scripts\python.exe -m uvicorn ml-service.app:app --host 0.0.0.0 --port 8000
```

**Terminal 2 — Backend:**
```bash
cd phishing-url-detector
node backend\server.js
```

**Verify both are running:**
- ML Service: http://localhost:8000/health → `{"status":"ok","model_loaded":true}`
- Backend: http://localhost:3001/api/health → `{"status":"ready",...}`

---

## Loading the Chrome Extension

1. Open Chrome → address bar → type `chrome://extensions` → Enter
2. Enable **Developer mode** (toggle, top-right corner)
3. Click **"Load unpacked"**
4. Select the `extension/` folder from this project
5. Click the puzzle icon 🧩 → pin **PhishGuard**

The shield icon will appear in your Chrome toolbar. Visit any website and click it to scan.

---

## Running Tests

```bash
# ML unit tests + full model evaluation (10,000 URLs)
.\venv\Scripts\python.exe ml\evaluate.py

# Comprehensive report: both models, 25 URLs, FP/FN analysis
.\venv\Scripts\python.exe full_report.py

# End-to-end API test (requires both services running)
.\venv\Scripts\python.exe live_api_test.py

# Backend integration tests (requires both services running)
node backend\tests\backend.test.js
```

### Test Results

```
ML Evaluation (10,000 URLs):   97% accuracy, ROC-AUC 0.9877
URL Predictions (25 URLs):     24/25 correct (1 FN: no-www domain)
Live API Test:                 12/12 ML service, 12/12 backend
Backend Integration:           14/14 passed
```

---

## API Reference

### POST /api/scan

```bash
curl -X POST http://localhost:3001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'
```

**Response:**
```json
{
  "success": true,
  "prediction": "legitimate",
  "risk_score": 0.987,
  "risk_level": "low",
  "message": "This URL appears to have the structure of a legitimate site.",
  "model_version": "3.0",
  "analyzed_url": "https://www.google.com",
  "scanned_at": "2026-10-19T07:30:00.000Z"
}
```

| Field | Description |
|---|---|
| `prediction` | `"legitimate"` or `"phishing"` |
| `risk_score` | 0.0 = phishing, 1.0 = legitimate |
| `risk_level` | `"low"` / `"medium"` / `"high"` |
| `analyzed_url` | URL sent to the model (normalized) |

### GET /api/health

```bash
curl http://localhost:3001/api/health
```

---

## How URL Normalization Works

Before sending a URL to the ML model, the backend **normalizes it to the domain only**. This prevents false positives on legitimate sites with complex URLs (e.g., Google Search results, YouTube video URLs).

```
Input from extension:
https://www.google.com/search?q=hello&sca_esv=abc123&rlz=...

Sent to ML model:
https://www.google.com
```

All phishing signals are in the **domain name**:
- Fake TLDs: `.tk`, `.gq`, `.xyz`
- Brand spoofing: `paypal-security-update.evil.com`  
- IP addresses: `http://192.168.1.1`
- No HTTPS

---

## Known Limitations

| Limitation | Reason |
|---|---|
| Some no-`www.` domains may be misclassified | Training data dominated by `www.site.com` patterns |
| URL-only analysis (no page content) | By design — never fetches the actual page (safe) |
| Requires local backend to run | Extension connects to `localhost:3001` |
| Dataset from 2023 | May miss very new phishing patterns |

---

## Tech Stack

| Layer | Technology |
|---|---|
| ML Model | XGBoost, Random Forest (scikit-learn) |
| ML Service | Python, FastAPI, Uvicorn |
| Backend | Node.js, Express, Axios |
| Extension | Chrome Manifest V3, Vanilla JS |
| Dataset | PhiUSIIL (235,370 URLs) |

---

## Dataset

**PhiUSIIL Phishing URL Dataset**  
- 235,370 URLs (134,850 legitimate, 100,520 phishing)
- Source: Kaggle
- Features: URL structure, domain analysis

The dataset CSV is **not included** in this repository (54 MB). Download it separately (see Installation step 2).

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Author

Built as a college project demonstrating end-to-end ML system development:  
from data → model training → REST API → Chrome extension.
