"""
Model loading, inference, and fallback logic.

Loads a serialized XGBoost pipeline from disk (or S3 via MODEL_PATH env var)
and provides a thread-safe `predict` function for the FastAPI endpoint.
"""

import os
import time
import logging
from pathlib import Path
from typing import Optional

import numpy as np
import joblib
import tldextract

from .features import extract_features, FEATURE_NAMES, NUM_FEATURES, TRUSTED_APEX

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global model state
# ---------------------------------------------------------------------------

_model = None
_model_loaded = False

# Path priority: MODEL_PATH env > default local path
DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "phishing_xgboost.joblib"


def get_model_path() -> Path:
    """Resolve the model artifact path."""
    env_path = os.environ.get("MODEL_PATH")
    if env_path:
        return Path(env_path)
    return DEFAULT_MODEL_PATH


def load_model() -> bool:
    """
    Load the trained model from disk.
    Returns True if the model was loaded successfully.
    """
    global _model, _model_loaded

    model_path = get_model_path()
    if not model_path.exists():
        logger.warning(f"Model file not found at {model_path}. Using fallback scoring.")
        _model_loaded = False
        return False

    try:
        _model = joblib.load(model_path)
        _model_loaded = True
        logger.info(f"Model loaded successfully from {model_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to load model from {model_path}: {e}")
        _model_loaded = False
        return False


def is_model_loaded() -> bool:
    return _model_loaded


def is_trusted_apex(url: str) -> bool:
    """True if the URL's effective apex (eTLD+1) is an official brand/popular site.

    Phishing impersonators almost never obtain the real brand apex (attacker apexes
    differ, e.g. paypal-secure-verify.tk), so a trusted apex is treated as benign.
    """
    try:
        ext = tldextract.extract(url)
        return bool(ext.domain and ext.domain.lower() in TRUSTED_APEX)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Fallback heuristic scorer (mirrors the old Node.js utils/ml.ts logic)
# ---------------------------------------------------------------------------

def _fallback_score(features: np.ndarray) -> tuple[float, float, list[str]]:
    """
    Simple rule-based scoring when no trained model is available.
    Returns (score, confidence, reasons).
    """
    score = 0.0
    reasons: list[str] = []

    # hostname entropy
    if features[23] > 4.5:
        score += 12
        reasons.append("High hostname entropy")

    # digit count in hostname
    if features[27] > 3:
        score += 8
        reasons.append("Many digits in hostname")

    # long URL
    if features[0] > 180:
        score += 6
        reasons.append("Long URL")

    # suspicious TLD
    if features[16] > 0.5:
        score += 8
        reasons.append("Suspicious TLD")

    # brand impersonation
    if features[31] > 0:
        score += 10
        reasons.append("Brand impersonation detected")

    # suspicious keywords
    if features[32] >= 2:
        score += 8
        reasons.append("Multiple suspicious keywords")

    # @ sign
    if features[11] > 0.5:
        score += 15
        reasons.append("Contains @ sign")

    # IP address as hostname
    if features[17] > 0.5:
        score += 10
        reasons.append("IP address used as hostname")

    # punycode
    if features[18] > 0.5:
        score += 10
        reasons.append("Punycode/IDN domain")

    # domain age
    age = features[40]
    if 0 <= age < 30:
        score += 12
        reasons.append("Very new domain")
    elif 0 <= age < 180:
        score += 6
        reasons.append("Recently created domain")

    # not https
    if features[28] < 0.5:
        score += 6
        reasons.append("Not HTTPS")

    # excessive subdomains
    if features[36] > 0.5:
        score += 8
        reasons.append("Excessive subdomain depth")

    score = max(0, min(100, round(score)))
    confidence = min(0.6, score / 100)  # low confidence for heuristic fallback
    return score, confidence, reasons


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

def predict(url: str, meta: Optional[dict] = None) -> dict:
    """
    Run prediction on a URL.

    Returns a dict with: score, label, confidence, top_features, inference_time_ms
    """
    start = time.perf_counter()

    # Trusted-apex guard: official brand/popular apex is treated as benign,
    # overriding the static model which otherwise over-flags legit brand pages.
    if is_trusted_apex(url):
        return {
            "score": 0,
            "label": "safe",
            "confidence": 0.0,
            "top_features": [],
            "inference_time_ms": round((time.perf_counter() - start) * 1000, 2),
        }

    features = extract_features(url, meta)

    if _model_loaded and _model is not None:
        try:
            X = features.reshape(1, -1)

            # Get probability predictions
            proba = _model.predict_proba(X)[0]
            phishing_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])

            score = int(round(phishing_prob * 100))
            confidence = float(phishing_prob)

            # Get feature importances for explainability
            top_features = _get_top_features(features)

        except Exception as e:
            logger.error(f"Model inference failed, using fallback: {e}")
            score, confidence, top_features = _fallback_score(features)
    else:
        score, confidence, top_features = _fallback_score(features)

    # Determine label
    if score >= 70:
        label = "phishing"
    elif score >= 40:
        label = "suspicious"
    else:
        label = "safe"

    elapsed_ms = (time.perf_counter() - start) * 1000

    return {
        "score": score,
        "label": label,
        "confidence": round(confidence, 4),
        "top_features": top_features if isinstance(top_features, list) else list(top_features),
        "inference_time_ms": round(elapsed_ms, 2),
    }


def _get_top_features(features: np.ndarray, top_k: int = 5) -> list[str]:
    """
    Return the top-k contributing features based on feature importance
    weighted by feature value.
    """
    if _model is None:
        return []

    try:
        # XGBoost exposes feature_importances_ on the classifier
        model = _model
        if hasattr(model, "named_steps"):
            # It's a sklearn Pipeline — get the classifier step
            model = model.named_steps.get("classifier", model)

        if hasattr(model, "feature_importances_"):
            importances = model.feature_importances_
            # Weight by actual feature values (non-zero features that matter)
            weighted = importances * np.abs(features)
            top_indices = np.argsort(weighted)[::-1][:top_k]
            return [FEATURE_NAMES[i] for i in top_indices if weighted[i] > 0]
    except Exception as e:
        logger.warning(f"Could not extract feature importances: {e}")

    return []
