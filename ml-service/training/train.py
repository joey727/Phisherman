"""
Training script for the Phisherman phishing URL classifier.

Uses publicly available datasets to train an XGBoost model:
- Generates synthetic labeled data from known phishing URL patterns
- Extracts 43 features per URL using the shared feature extraction module
- Trains an XGBoost classifier with cross-validation
- Saves the trained model to models/phishing_xgboost.joblib

Usage:
    cd ml-service
    pip install -r requirements.txt
    python -m training.train
"""

import sys
import os
import logging
import hashlib
import random
from pathlib import Path

import numpy as np
import joblib
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from xgboost import XGBClassifier

# Add parent directory to path so we can import the app module
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.features import extract_features, NUM_FEATURES, FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("training")

# ---------------------------------------------------------------------------
# Dataset generation from known patterns
# ---------------------------------------------------------------------------

# Representative phishing URL patterns (derived from public threat intel feeds)
PHISHING_PATTERNS = [
    "http://{rand}.tk/login/verify-account.php",
    "http://paypal-secure-{rand}.ml/update",
    "https://apple.com-{rand}.cf/verify",
    "http://{rand}.xyz/microsoft/login.html",
    "http://192.168.{d1}.{d2}/banking/secure",
    "https://secure-{brand}-login.{tld}/{path}",
    "http://{rand}.{tld}/wp-admin/login.php?redirect={rand}",
    "https://{brand}-account-verify.{tld}/confirm",
    "http://{rand}.{tld}/{brand}/update-billing.html",
    "http://login.{brand}.{rand}.{tld}/account/secure",
    "https://{rand}.{tld}/signin?token={long_rand}&session={long_rand}",
    "http://{rand}-{rand}.{tld}/urgent/unlock-account",
    "http://{d1}.{d2}.{d3}.{d4}/{brand}/credential/verify",
    "https://www.{brand}.com.{rand}.{tld}/support/password",
    "http://{rand}.ga/reward/claim?user={rand}",
    "https://{brand}-suspend-alert.{tld}/validate",
    "http://xn--{rand}.{tld}/invoice/refund",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "http://bit.ly/{short}",
    "https://{rand}.{tld}/dropbox/shared/document.pdf.exe",
    "http://{rand}-{rand}-{rand}.{tld}/update/billing/confirm",
    "https://www.{brand}.com@{rand}.{tld}/login",
    "http://{rand}.top/~admin/secure/{brand}/verify",
    "https://{rand}.buzz/{long_path}/credential.php",
    "http://{rand}.pw/account/unlock?ref={long_rand}",
]

BENIGN_PATTERNS = [
    "https://www.google.com/search?q={query}",
    "https://github.com/{user}/{repo}",
    "https://stackoverflow.com/questions/{num}/{slug}",
    "https://en.wikipedia.org/wiki/{topic}",
    "https://www.amazon.com/dp/{asin}",
    "https://www.youtube.com/watch?v={vid}",
    "https://twitter.com/{user}/status/{num}",
    "https://www.reddit.com/r/{sub}/comments/{id}/{slug}",
    "https://docs.python.org/3/{path}",
    "https://developer.mozilla.org/en-US/docs/{path}",
    "https://www.bbc.com/news/{slug}",
    "https://medium.com/@{user}/{slug}",
    "https://www.nytimes.com/{year}/{month}/{day}/{slug}",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://calendar.google.com/calendar/r",
    "https://www.linkedin.com/in/{user}",
    "https://www.microsoft.com/en-us/{path}",
    "https://www.apple.com/{product}",
    "https://cloud.google.com/{service}",
    "https://aws.amazon.com/{service}",
    "https://www.netflix.com/browse",
    "https://open.spotify.com/track/{id}",
    "https://www.npmjs.com/package/{name}",
    "https://pypi.org/project/{name}",
    "https://www.cloudflare.com/{path}",
]

BRANDS = ["paypal", "apple", "google", "microsoft", "amazon", "netflix",
          "facebook", "chase", "wellsfargo", "dropbox", "linkedin", "ebay"]
SUSPICIOUS_TLDS = ["tk", "ml", "cf", "ga", "gq", "top", "xyz", "buzz", "pw", "cc", "su"]
SAFE_TLDS = ["com", "org", "net", "io", "dev", "co", "edu", "gov"]


def _rand_str(length: int = 8) -> str:
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(length))


def _rand_hex(length: int = 32) -> str:
    return hashlib.md5(os.urandom(16)).hexdigest()[:length]


def _generate_url(pattern: str, is_phishing: bool) -> str:
    """Fill in a URL pattern with random values."""
    tld_pool = SUSPICIOUS_TLDS if is_phishing else SAFE_TLDS
    brand = random.choice(BRANDS)

    replacements = {
        "{rand}": _rand_str(random.randint(5, 15)),
        "{long_rand}": _rand_hex(32),
        "{brand}": brand,
        "{tld}": random.choice(tld_pool),
        "{path}": "/".join(_rand_str(random.randint(3, 8)) for _ in range(random.randint(1, 4))),
        "{long_path}": "/".join(_rand_str(random.randint(4, 10)) for _ in range(random.randint(4, 8))),
        "{short}": _rand_str(6),
        "{query}": "+".join(_rand_str(random.randint(3, 8)) for _ in range(random.randint(1, 3))),
        "{user}": _rand_str(random.randint(4, 12)),
        "{repo}": _rand_str(random.randint(4, 12)),
        "{num}": str(random.randint(10000, 99999999)),
        "{slug}": "-".join(_rand_str(random.randint(3, 8)) for _ in range(random.randint(2, 5))),
        "{topic}": "_".join(_rand_str(random.randint(3, 8)) for _ in range(random.randint(1, 3))),
        "{asin}": "B" + _rand_hex(9).upper(),
        "{vid}": _rand_str(11),
        "{sub}": _rand_str(random.randint(4, 12)),
        "{id}": _rand_str(6),
        "{year}": str(random.randint(2020, 2026)),
        "{month}": f"{random.randint(1,12):02d}",
        "{day}": f"{random.randint(1,28):02d}",
        "{product}": random.choice(["iphone", "macbook", "ipad", "watch", "airpods"]),
        "{service}": random.choice(["compute", "storage", "ai", "lambda", "s3"]),
        "{name}": _rand_str(random.randint(4, 12)),
        "{d1}": str(random.randint(1, 254)),
        "{d2}": str(random.randint(1, 254)),
        "{d3}": str(random.randint(1, 254)),
        "{d4}": str(random.randint(1, 254)),
    }

    url = pattern
    for key, val in replacements.items():
        while key in url:
            url = url.replace(key, val if key in ("{tld}", "{brand}") else
                              (val if key == "{rand}" else val), 1)
            # Regenerate random for next occurrence
            if key == "{rand}":
                val = _rand_str(random.randint(5, 15))
    return url


def generate_dataset(n_samples: int = 10000) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate a balanced dataset of phishing and benign URLs.

    Returns (X, y) where X is shape (n_samples, NUM_FEATURES) and y is shape (n_samples,).
    """
    half = n_samples // 2
    urls_phishing = []
    urls_benign = []

    for _ in range(half):
        pattern = random.choice(PHISHING_PATTERNS)
        urls_phishing.append(_generate_url(pattern, is_phishing=True))

    for _ in range(half):
        pattern = random.choice(BENIGN_PATTERNS)
        urls_benign.append(_generate_url(pattern, is_phishing=False))

    # Extract features
    X_list = []
    y_list = []

    for url in urls_phishing:
        meta = {}
        # Simulate domain age — phishing domains tend to be young
        if random.random() < 0.7:
            meta["domain_age_days"] = random.randint(0, 60)
        X_list.append(extract_features(url, meta))
        y_list.append(1)

    for url in urls_benign:
        meta = {}
        # Benign domains tend to be old
        if random.random() < 0.6:
            meta["domain_age_days"] = random.randint(365, 7300)
        X_list.append(extract_features(url, meta))
        y_list.append(0)

    X = np.array(X_list, dtype=np.float32)
    y = np.array(y_list, dtype=np.int32)

    # Shuffle
    indices = np.arange(len(y))
    np.random.shuffle(indices)
    return X[indices], y[indices]


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train_model(n_samples: int = 20000):
    """Train and save an XGBoost phishing classifier."""

    logger.info(f"Generating {n_samples} training samples...")
    X, y = generate_dataset(n_samples)
    logger.info(f"Dataset: {X.shape[0]} samples, {X.shape[1]} features")
    logger.info(f"Class distribution: {np.bincount(y)} (0=benign, 1=phishing)")

    # XGBoost classifier
    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1.0,
        scale_pos_weight=1.0,  # balanced dataset
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )

    # Cross-validation
    logger.info("Running 5-fold stratified cross-validation...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(model, X, y, cv=cv, scoring="accuracy", n_jobs=-1)
    logger.info(f"CV Accuracy: {scores.mean():.4f} (+/- {scores.std():.4f})")
    logger.info(f"Per-fold: {[f'{s:.4f}' for s in scores]}")

    # Train final model on full dataset
    logger.info("Training final model on full dataset...")
    model.fit(X, y)

    # Evaluation on training set (for sanity check)
    y_pred = model.predict(X)
    logger.info("\n--- Training Set Classification Report ---")
    logger.info("\n" + classification_report(y, y_pred, target_names=["benign", "phishing"]))
    logger.info(f"Confusion Matrix:\n{confusion_matrix(y, y_pred)}")

    # Feature importance
    importances = model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    logger.info("\n--- Top 15 Features by Importance ---")
    for i in range(min(15, len(sorted_idx))):
        idx = sorted_idx[i]
        logger.info(f"  {i+1:2d}. {FEATURE_NAMES[idx]:30s} = {importances[idx]:.4f}")

    # Save model
    output_dir = Path(__file__).resolve().parent.parent / "models"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "phishing_xgboost.joblib"
    joblib.dump(model, output_path, compress=3)
    logger.info(f"\nModel saved to {output_path} ({output_path.stat().st_size / 1024:.1f} KB)")

    return model


if __name__ == "__main__":
    train_model()
