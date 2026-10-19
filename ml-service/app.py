"""
app.py  —  PhishGuard ML Inference Service
==========================================
A FastAPI application that loads the trained phishing detection model
and provides a REST API for making predictions.

This runs separately from the Node.js backend.
Node.js sends URLs here; we return predictions.

Start with:
  uvicorn ml-service.app:app --host 0.0.0.0 --port 8000 --reload
  (run from the project root)

Or from inside the ml-service folder:
  cd ml-service
  uvicorn app:app --host 0.0.0.0 --port 8000 --reload
"""

import os
import sys
import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
import urllib.parse

# ------------------------------------------------------------------
# Add the ml/ directory to the Python path so we can import
# feature_extractor.py (which lives in ml/, not ml-service/)
# ------------------------------------------------------------------
ML_DIR = Path(__file__).parent.parent / "ml"
sys.path.insert(0, str(ML_DIR))

from feature_extractor import FEATURE_NAMES, extract_features_as_list  # noqa: E402

# ------------------------------------------------------------------
# Logging setup — logs to console (visible in your terminal)
# ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Model artifact paths
# ------------------------------------------------------------------
MODELS_DIR = ML_DIR / "models"
MODEL_PATH = MODELS_DIR / "phishing_model.pkl"
FEATURE_NAMES_PATH = MODELS_DIR / "feature_names.pkl"
VERSION_PATH = MODELS_DIR / "model_version.txt"

# ------------------------------------------------------------------
# Global model state — loaded once at startup, reused for every request
# ------------------------------------------------------------------
model = None           # the trained sklearn/xgboost model
model_version = "unknown"
model_ready = False    # False until model loads successfully


# ------------------------------------------------------------------
# FastAPI app setup
# ------------------------------------------------------------------
app = FastAPI(
    title="PhishGuard ML Service",
    description="Phishing URL detection using machine learning",
    version="1.0",
    docs_url="/docs",       # Swagger UI at /docs
    redoc_url="/redoc",
)

# Allow requests from the Node.js backend only.
# In production, replace "http://localhost:3001" with your actual backend URL.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3001", "http://127.0.0.1:3001"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# ------------------------------------------------------------------
# Load model at application startup
# ------------------------------------------------------------------
@app.on_event("startup")
async def load_model_on_startup():
    """
    Load the trained model once when the server starts.
    This avoids reloading it on every request (which would be slow).
    """
    global model, model_version, model_ready

    if not MODEL_PATH.exists():
        logger.warning(
            f"Model not found at {MODEL_PATH}. "
            "Start the service after running: python ml/train.py"
        )
        return

    try:
        # Load model
        model = joblib.load(MODEL_PATH)
        logger.info(f"Model loaded from {MODEL_PATH}")

        # Verify saved feature names match the current extractor
        if FEATURE_NAMES_PATH.exists():
            saved_features = joblib.load(FEATURE_NAMES_PATH)
            if saved_features != FEATURE_NAMES:
                logger.error(
                    "Feature name mismatch between saved model and feature_extractor.py. "
                    "Retrain the model."
                )
                return
            logger.info(f"Feature schema verified: {len(FEATURE_NAMES)} features")

        # Read version string
        if VERSION_PATH.exists():
            model_version = VERSION_PATH.read_text().strip()

        model_ready = True
        logger.info(f"ML service ready. Model version: {model_version}")

    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        # Don't crash the server — /health will report not ready


# ------------------------------------------------------------------
# Input/Output schemas (Pydantic validates these automatically)
# ------------------------------------------------------------------
class PredictRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        # Reject empty strings
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")

        # Enforce a reasonable length limit
        # The longest URL in our dataset was ~6000 chars; 8000 is a safe cap
        if len(v) > 8000:
            raise ValueError("URL is too long (max 8000 characters)")

        # Must have a recognizable scheme
        try:
            parsed = urllib.parse.urlparse(v)
        except Exception:
            raise ValueError("URL could not be parsed")

        if parsed.scheme not in ("http", "https", "ftp"):
            raise ValueError(
                f"Unsupported URL scheme '{parsed.scheme}'. "
                "Only http, https, and ftp are supported."
            )

        if not parsed.netloc:
            raise ValueError("URL must include a hostname")

        return v


class PredictResponse(BaseModel):
    success: bool
    prediction: str        # "phishing" or "legitimate"
    risk_score: float      # 0.0 = very likely phishing, 1.0 = very likely legitimate
    model_version: str
    message: str           # human-readable explanation


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------
@app.get("/health")
async def health_check():
    """
    Returns the readiness status of the service and the model.
    The Node.js backend calls this to verify we're up before forwarding requests.
    """
    return {
        "status": "ok" if model_ready else "model_not_ready",
        "model_loaded": model_ready,
        "model_version": model_version,
        "feature_count": len(FEATURE_NAMES),
    }


@app.post("/predict", response_model=PredictResponse)
async def predict(request: PredictRequest):
    """
    Accept a URL and return a phishing prediction.

    risk_score explanation:
      - 0.0 to 0.4 : HIGH RISK — model strongly suspects phishing
      - 0.4 to 0.6 : UNCERTAIN — model is not confident
      - 0.6 to 1.0 : LOW RISK  — model thinks this is legitimate
    
    Important: risk_score is NOT a calibrated probability.
    It is the model's raw output — treat it as a relative indicator.
    """
    if not model_ready:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "model_not_ready",
                "message": "The ML model is not loaded. Run 'python ml/train.py' first."
            }
        )

    url = request.url

    # Extract features using the same pipeline as training
    # IMPORTANT: We never fetch the URL — only analyze its text structure
    try:
        feature_values = extract_features_as_list(url)
    except Exception as e:
        logger.error(f"Feature extraction failed for URL: {url[:100]} — {e}")
        raise HTTPException(
            status_code=422,
            detail={"error": "feature_extraction_failed", "message": str(e)}
        )

    # Build the feature DataFrame the model expects
    # IMPORTANT: use a named DataFrame — the model was trained on
    # a DataFrame with FEATURE_NAMES columns, so we must match that
    # at inference time to get correct predictions.
    feature_df = pd.DataFrame([feature_values], columns=FEATURE_NAMES)

    try:
        # predict() returns 0 (phishing) or 1 (legitimate)
        label = int(model.predict(feature_df)[0])

        # predict_proba() returns [[prob_phishing, prob_legitimate]]
        proba = model.predict_proba(feature_df)[0]
        prob_legitimate = float(proba[1])

        # risk_score: 0 = definitely phishing, 1 = definitely legitimate
        # We use prob_legitimate directly as the "safety score"
        risk_score = round(prob_legitimate, 4)

    except Exception as e:
        logger.error(f"Model prediction failed: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": "prediction_failed", "message": "Internal model error"}
        )

    prediction = "legitimate" if label == 1 else "phishing"

    # Build a human-readable message based on the score
    if risk_score < 0.4:
        message = (
            "This URL shows multiple characteristics associated with phishing sites, "
            "such as suspicious domain patterns, unusual character ratios, or no HTTPS."
        )
    elif risk_score < 0.6:
        message = (
            "This URL has some unusual characteristics. Exercise caution before "
            "entering personal information on this site."
        )
    else:
        message = (
            "This URL appears to have the structural characteristics of a legitimate website. "
            "However, always verify websites before entering sensitive information."
        )

    # Log the prediction (but NOT the full URL to protect privacy)
    logger.info(
        f"Prediction: {prediction} | risk_score={risk_score:.3f} | "
        f"url_length={len(url)} | scheme={url.split('://')[0] if '://' in url else 'unknown'}"
    )

    return PredictResponse(
        success=True,
        prediction=prediction,
        risk_score=risk_score,
        model_version=model_version,
        message=message,
    )
