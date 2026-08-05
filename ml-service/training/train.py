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
    "http://{platform}-secure-verify.{tld}/login",
    "https://dashboard-{platform}-account.{tld}/signin",
    "http://{platform}.{rand}.{tld}/account/update",
    "https://login.{platform}.{rand}.{tld}/oauth/confirm",
    "https://{brand}-support.{rand}.{tld}/{platform}/billing",
    "https://{brand}-account.{rand}.com/signin",
    "https://login-{rand}-verify.{rand}.co/confirm",
    "https://xn--{rand}.com-account-verify/signin",
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
    "https://dashboard.{platform}.com/{path}",
    "https://console.{platform}.com/{path}",
    "https://app.{platform}.com/{path}",
    "https://docs.{platform}.com/{path}",
    "https://support.{platform}.com/{path}",
    "https://cloud.{platform}.com/{path}",
    "https://{platform}.com/{path}",
    "https://www.{platform}.com/{path}",
    "https://{platform}.com/login",
    "https://{platform}.com/account/{path}",
]

BRANDS = ["paypal", "apple", "google", "microsoft", "amazon", "netflix",
          "facebook", "chase", "wellsfargo", "dropbox", "linkedin", "ebay"]
PLATFORMS = [
    "render", "stripe", "heroku", "fly", "digitalocean", "linode",
    "github", "npmjs", "pypi", "cloudflare", "vercel", "netlify",
]
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
        "{platform}": random.choice(PLATFORMS),
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


def generate_benign(n: int) -> list[str]:
    """Generate n synthetic benign URLs from the benign patterns (fallback dataset)."""
    return [
        _generate_url(random.choice(BENIGN_PATTERNS), is_phishing=False)
        for _ in range(n)
    ]


# Common words seen in real-world benign doc/blog/support paths. Used by
# generate_benign_docs to teach the model that word-based deep paths on
# legitimate-looking domains (docs, manuals, blog posts) are benign, rather than
# the alphanumeric random paths produced by BENIGN_PATTERNS.
DOC_PATH_WORDS = [
    "docs", "home", "getting-started", "user-guide", "api", "reference",
    "tutorials", "blog", "news", "products", "pricing", "about", "contact",
    "privacy", "terms", "downloads", "releases", "faq", "help", "support",
    "manual", "guide", "intro", "handbook", "install", "core", "ui",
    "components", "themes", "plugins", "integrations", "enterprise",
    "community", "solutions", "resources", "documentation",
]

DOC_TLDS = ["io", "org", "com", "dev", "net", "co"]


def generate_benign_docs(n: int) -> list[str]:
    """Generate n synthetic benign URLs shaped like real doc/blog/support pages.

    Uses realistic word paths and domains of varied lengths (including short
    domains and short digit-bearing domains) so the classifier learns the class
    "word-path on a legitimate-looking domain" instead of over-relying on the
    trusted-apex allowlist.
    """
    out = []
    for _ in range(n):
        n_chars = random.choice([2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13])
        if n_chars <= 4 and random.random() < 0.5:
            domain = random.choice("abcdefghijklmnopqrstuvwxyz") + str(random.randint(0, 9))
        else:
            domain = "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(n_chars))
        if random.random() < 0.4:
            domain = "www." + domain
        suffix = random.choice(DOC_TLDS)
        n_segments = random.randint(1, 4)
        segments = [random.choice(DOC_PATH_WORDS) for _ in range(n_segments)]
        path = "/" + "/".join(segments) + "/"
        out.append(f"https://{domain}.{suffix}{path}")
    return out


def generate_phishing(n: int) -> list[str]:
    """Generate n synthetic phishing URLs from the phishing patterns (fallback dataset)."""
    return [
        _generate_url(random.choice(PHISHING_PATTERNS), is_phishing=True)
        for _ in range(n)
    ]


# ---------------------------------------------------------------------------
# Shared training utilities (used by both the synthetic trainer and pipeline.py)
# ---------------------------------------------------------------------------

def build_classifier() -> XGBClassifier:
    """Return a new classifier with the project's standard hyperparameters."""
    return XGBClassifier(
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


def train_on_dataset(
    X: np.ndarray, y: np.ndarray, test_size: float = 0.15
) -> tuple[XGBClassifier, dict]:
    """
    Hold-out trained by default split; returns (model, metrics).
    Metrics dict: {precision, recall, f1, accuracy, n, pos_rate}.
    """
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (
        precision_recall_fscore_support,
        accuracy_score,
    )

    X_tr, X_va, y_tr, y_va = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=42
    )
    clf = build_classifier()
    clf.fit(X_tr, y_tr)

    proba = clf.predict_proba(X_va)[:, 1]
    pred = (proba >= 0.5).astype(int)
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_va, pred, average="binary", pos_label=1, zero_division=0
    )
    metrics = {
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "accuracy": float(accuracy_score(y_va, pred)),
        "training_n": int(len(y)),
        "validation_n": int(len(y_va)),
        "pos_rate_train": float(y.mean()),
    }
    return clf, metrics


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
    model = build_classifier()

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
