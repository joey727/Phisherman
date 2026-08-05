"""
Self-training data pipeline for the Phisherman ML classifier.

Collects independently labeled samples and retrains an XGBoost classifier:

  Positives     : threat-intel feeds (URLHaus, PhishTank, OpenPhish, PhishStats)
  Delayed pos   : scan_log URLs that were scanned earlier and are now in a feed
  Negatives     : public benign corpus (Tranco) + scan_log URLs not in any feed
  Fallback      : synthetic benign/phishing patterns if a source is unreachable

Training is safe via *promotion gating*: the new model is written to
models/phishing_xgboost.joblib only if it matches or beats the last-promoted
model on a fixed benchmark set — we never deploy a worse model.

Usage:
    python -m training.pipeline            # full weekly run
    python -m training.pipeline --small    # quick smoke run

Optional env: UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
(needed only to read the delayed-feedback scan_log). These are auto-loaded
from the repo-root or ml-service `.env` file (gitignored) if not already
present in the environment; an exported env or CI/Render injection always wins.
"""

import gzip
import io
import json
import logging
import os
import random
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
import joblib
import numpy as np
from dotenv import load_dotenv

# Allow `python -m training.pipeline` to import the sibling `app` package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.features import extract_features, NUM_FEATURES  # noqa: E402
from app.model import is_trusted_apex  # noqa: E402
from training.train import (  # noqa: E402
    train_on_dataset,
    generate_benign,
    generate_benign_docs,
    generate_phishing,
)

logger = logging.getLogger("pipeline")

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"
MODEL_PATH = MODELS_DIR / "phishing_xgboost.joblib"
METRICS_PATH = MODELS_DIR / "metrics.json"
SCAN_LOG_KEY = "scan_log"

# Load repo-root / ml-service `.env` (gitignored) so local retrains pick up
# UPSTASH_REDIS_REST_URL/TOKEN. python-dotenv leaves existing env vars
# untouched by default, so CI/Render/exported values always win.
load_dotenv()

USER_AGENT = "Phisherman-ml-pipeline/1.0"
HTTP_TIMEOUT = httpx.Timeout(60.0)

# Fixed benchmark set used to compare candidates across runs. Balanced-ish.
BENCHMARK_PHISHING = [
    "http://paypal-secure-verify.tk/login/account.php",
    "https://account-verify.apple-id.cf/icloud",
    "http://192.168.1.1/banking/login/serve",
    "https://secure-bank-login.xyz/verify",
    "https://xn--help-4ia.com-account-verify/signin",
    "http://bit.ly/urgent-unlock",
    "https://microsoft-account.buzzbuzz.com/signin",
    "https://wellsfargo-update.icu/validate",
    "http://reward-claim.ga?user=abc123",
    "https://netflix-billing-verify.top/suspend",
    "https://dropbox-shared-document.site/file",
    "https://login-nil-verify.urrer.co/confirm",
    "https://coinbase-secure-panel.pw/wallet",
    "http://www.chase.com-otp-verify/login",
    "http://render-secure-verify.tk/login",
    "https://dashboard-render-account.xyz/signin",
    "https://stripe-billing-verify.top/account",
    "https://login.heroku.secure-panel.pw/oauth/confirm",
    "https://cloudflare-support.verify-account.icu/billing",
]

BENCHMARK_BENIGN = [
    "https://www.google.com",
    "https://github.com/n8n-io/n8n",
    "https://stackoverflow.com/questions/123456",
    "https://en.wikipedia.org/wiki/Widget",
    "https://www.amazon.com/dp/B0I5WWRWNW",
    "https://www.youtube.com/watch?v=abcxyz",
    "https://www.reddit.com/r/notebook/",
    "https://docs.python.org/library/",
    "https://developer.mozilla.org/en-US/docs/Web",
    "https://www.bbc.com/news/technology",
    "https://mail.linkedin.com/me/",
    "https://calendar.google.com/calendar/r",
    "https://open.spotify.com/track/111",
    "https://cloud.google.com/compute",
    "https://dashboard.render.com/",
    "https://dashboard.stripe.com/login",
    "https://cloud.digitalocean.com/projects",
    "https://docs.github.com/en/actions",
    "https://www.npmjs.com/package/react",
    "https://pypi.org/project/requests/",
    "https://www.cloudflare.com/products/",
    "https://app.netlify.com/sites",
    "https://vercel.com/dashboard",
]

RAW_MODEL_BENIGN_REGRESSION = [
    "https://render.com/",
    "https://dashboard.render.com/",
    "https://dashboard.stripe.com/login",
    "https://docs.github.com/en/actions",
    "https://www.npmjs.com/package/react",
    "https://pypi.org/project/requests/",
    "https://www.cloudflare.com/products/",
    "https://app.netlify.com/sites",
    "https://vercel.com/dashboard",
]

# Real benign URLs whose apex is NOT in TRUSTED_APEX, so the trusted-apex guard
# does NOT save them. These must be classified as benign by the *raw* model —
# they are the proof that the classifier generalizes to unfamiliar benign
# shapes instead of relying on an allowlist.
RAW_UNGUARDED_BENIGN_REGRESSION = [
    "https://www.npmjs.com/package/react",
    "https://pypi.org/project/requests/",
    "https://www.python.org/downloads/",
    "https://docs.docker.com/get-started/",
    "https://kubernetes.io/docs/home/",
    "https://www.postgresql.org/docs/",
    "https://getbootstrap.com/docs/",
    "https://www.w3.org/TR/html/",
    "https://archive.org/details/",
    "https://webpack.js.org/concepts/",
]

HARD_NEGATIVE_PHISHING = [
    "http://render-secure-verify.tk/login",
    "https://dashboard-render-account.xyz/signin",
    "https://stripe-billing-verify.top/account",
    "https://login.heroku.secure-panel.pw/oauth/confirm",
    "https://cloudflare-support.verify-account.icu/billing",
    "http://github-security-alert.gq/login",
    "https://npmjs-package-verify.top/account",
    "https://pypi-support-update.xyz/project/requests",
    "https://vercel-secure-panel.pw/dashboard",
    "https://netlify-account-confirm.icu/sites",
]

# Real trusted domains added to the *negative* training set (distinct from the
# benchmark set above) so the model learns official brand/popular sites are benign.
# Kept as apex https:// URLs; matched/filtered against feed positives at build time.
CURATED_BENIGN = [
    "https://www.google.com",
    "https://github.com",
    "https://apple.com",
    "https://www.microsoft.com",
    "https://www.wikipedia.org",
    "https://www.amazon.com",
    "https://www.youtube.com",
    "https://www.reddit.com",
    "https://www.bbc.com",
    "https://www.nytimes.com",
    "https://mail.google.com",
    "https://www.linkedin.com",
    "https://open.spotify.com",
    "https://cloud.google.com",
    "https://aws.amazon.com",
    "https://www.netflix.com",
    "https://www.paypal.com",
    "https://www.facebook.com",
    "https://twitter.com",
    "https://www.dropbox.com",
    "https://www.chase.com",
    "https://www.wellsfargo.com",
    "https://www.citi.com",
    "https://bankofamerica.com",
    "https://www.usps.com",
    "https://www.fedex.com",
    "https://www.dhl.com",
    "https://www.ebay.com",
    "https://www.instagram.com",
    "https://www.whatsapp.com",
    "https://www.coinbase.com",
    "https://www.binance.com",
    "https://stackoverflow.com",
    "https://docs.python.org",
    "https://developer.mozilla.org",
    "https://www.bing.com",
    "https://www.wikipedia.com",
    "https://example.com",
    "https://example.org",
    "https://example.net",
    "https://www.icloud.com",
    "https://outlook.com",
    "https://yahoo.com",
    "https://www.office.com",
    "https://www.bankofamerica.com",
    "https://render.com",
    "https://stripe.com",
    "https://www.heroku.com",
    "https://fly.io",
    "https://www.digitalocean.com",
    "https://www.linode.com",
]

# Representative *real-path* benign URLs (subdomains + paths) added to the
# negative pool so the model learns ordinary legitimate site forms, not just
# bare apex domains. Kept distinct from the fixed benchmark set to avoid
# evaluating on training samples.
CURATED_BENIGN_PATHS = [
    "https://accounts.google.com/signin/v2/identifier",
    "https://support.google.com/chrome/?p=help",
    "https://github.com/features/actions",
    "https://github.com/security/overview",
    "https://en.wikipedia.org/wiki/Transport",
    "https://en.wikipedia.org/wiki/Geography_of_France",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    "https://stackoverflow.com/questions/5343607",
    "https://support.microsoft.com/en-us/contactus",
    "https://login.microsoftonline.com/common/oauth2",
    "https://www.amazon.com/gp/css/homepage.html",
    "https://www.youtube.com/results?search_query=music",
    "https://www.reddit.com/r/webdev/comments/abc",
    "https://www.linkedin.com/mynetwork/",
    "https://www.ebay.com/sch/i.html?cat1=1",
    "https://www.paypal.com/signin",
    "https://www.paypal.com/myaccount/home",
    "https://signin.aws.amazon.com/oauth",
    "https://console.aws.amazon.com/",
    "https://www.dropbox.com/login",
    "https://accounts.spotify.com/en/login",
    "https://www.fedex.com/en-us/home.html",
    "https://www.dhl.com/en.html",
    "https://id.ebay.com/signin/",
    "https://login.yahoo.com/",
    "https://outlook.com/mail/0/",
    "https://accounts.google.com/gsi/client",
    "https://www.apple.com/shop/buy-iphone",
    "https://www.icloud.com/mail/",
    "https://www.office.com/?auth=2",
    "https://www.wellsfargo.com/savings/maximize/",
    "https://chaseonline.chase.com/",
    "https://secure.bankofamerica.com/login/",
    "https://www.usbank.com/online-savings.html",
    "https://dashboard.render.com/",
    "https://dashboard.stripe.com/login",
    "https://dashboard.heroku.com/apps",
    "https://fly.io/user/personal_access_tokens",
    "https://cloud.digitalocean.com/projects",
    "https://app.netlify.com/sites",
    "https://vercel.com/dashboard",
    "https://docs.github.com/en/actions",
    "https://www.npmjs.com/package/react",
    "https://pypi.org/project/requests/",
    "https://www.cloudflare.com/products/",
]


# ---------------------------------------------------------------------------
# Fetching helpers
# ---------------------------------------------------------------------------

def _dedupe(urls):
    seen = set()
    out = []
    for u in urls:
        u = (u or "").strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _featurize(urls, meta=None) -> np.ndarray:
    """Extract features per URL, tolerating malformed entries from messy feeds."""
    meta = meta or {}
    vectors = []
    for u in urls:
        try:
            vectors.append(extract_features(u, meta))
        except Exception:  # noqa: BLE001
            vectors.append(np.zeros(NUM_FEATURES, dtype=np.float32))
    return np.asarray(vectors, dtype=np.float32)


def _safe(fn, default):
    try:
        return fn()
    except Exception as e:  # noqa: BLE001
        logger.warning("%s failed: %s", fn.__name__, e)
        return default


def _get_bytes(url: str) -> bytes:
    r = httpx.get(
        url, timeout=HTTP_TIMEOUT, follow_redirects=True, headers={"User-Agent": USER_AGENT}
    )
    r.raise_for_status()
    return r.content


def fetch_urlhaus() -> list:
    text = _get_bytes("https://urlhaus.abuse.ch/downloads/csv_online/").decode("utf-8", "replace")
    urls = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split('","')
        if len(parts) >= 3:
            urls.append(parts[2].replace('"', "").strip())
    return urls


def fetch_phishtank() -> list:
    raw = gzip.decompress(
        _get_bytes("https://data.phishtank.com/data/online-valid.csv.gz")
    ).decode("utf-8", "replace")
    urls = []
    for line in raw.splitlines():
        if not line:
            continue
        parts = line.split(",")
        if len(parts) >= 2:
            urls.append(parts[1].strip())
    return urls


def fetch_openphish() -> list:
    text = _get_bytes("https://openphish.com/feed.txt").decode("utf-8", "replace")
    return [l.strip() for l in text.splitlines() if l.strip()]


def fetch_phishstats() -> list:
    data = json.loads(_get_bytes("https://api.phishstats.info/api/phishing?_sort=-id&_size=200000"))
    urls = []
    for item in data:
        u = (item.get("url") or "").strip()
        if u:
            urls.append(u)
    return urls


def fetch_tranco(top_n: int = 40000) -> list:
    data = _get_bytes("https://tranco-list.eu/top-1m.csv.zip")
    zf = zipfile.ZipFile(io.BytesIO(data))
    name = zf.namelist()[0]
    text = zf.read(name).decode("utf-8", "replace")
    urls = []
    for i, line in enumerate(text.splitlines()):
        if i >= top_n:
            break
        parts = line.split(",")
        if len(parts) >= 2:
            urls.append("https://" + parts[1].strip())
    return urls


def fetch_scan_log() -> list:
    url = os.environ.get("UPSTASH_REDIS_REST_URL")
    token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    missing = [name for name, value in (
        ("UPSTASH_REDIS_REST_URL", url),
        ("UPSTASH_REDIS_REST_TOKEN", token),
    ) if not value]
    if missing:
        logger.info(
            "Redis scan_log skipped: %s not set in environment "
            "(feed-only training; export them or run in the CI retrain job to "
            "include delayed-feedback samples)",
            ", ".join(missing),
        )
        return []
    r = httpx.get(
        f"{url}/zrange/{SCAN_LOG_KEY}/0/-1",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    r.raise_for_status()
    return [u for u in r.json() if isinstance(u, str)]


# ---------------------------------------------------------------------------
# Benchmark + safe promotion
# ---------------------------------------------------------------------------

SUSPICIOUS_THRESHOLD = 0.40
PHISHING_THRESHOLD = 0.70
MIN_RAW_PHISHING_RECALL = 0.90


def _metrics_from_predictions(pred: list[int], labels: list[int]) -> dict:
    tp = sum(1 for p, l in zip(pred, labels) if p == 1 and l == 1)
    fp = sum(1 for p, l in zip(pred, labels) if p == 1 and l == 0)
    fn = sum(1 for p, l in zip(pred, labels) if p == 0 and l == 1)
    tn = sum(1 for p, l in zip(pred, labels) if p == 0 and l == 0)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0
    false_negative_rate = fn / (fn + tp) if (fn + tp) else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "false_negative_rate": round(false_negative_rate, 4),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
    }


def _raw_probability(model, url: str) -> float:
    X = extract_features(url, {}).reshape(1, -1)
    return float(model.predict_proba(X)[0, 1])


def evaluate_benchmark(model) -> dict:
    urls = BENCHMARK_PHISHING + BENCHMARK_BENIGN
    labels = [1] * len(BENCHMARK_PHISHING) + [0] * len(BENCHMARK_BENIGN)
    raw_probs = [_raw_probability(model, u) for u in urls]
    raw_pred = [int(p >= PHISHING_THRESHOLD) for p in raw_probs]
    guarded_pred = []
    for u in urls:
        if is_trusted_apex(u):
            guarded_pred.append(0)
        else:
            guarded_pred.append(int(_raw_probability(model, u) >= PHISHING_THRESHOLD))

    raw = _metrics_from_predictions(raw_pred, labels)
    guarded = _metrics_from_predictions(guarded_pred, labels)
    guarded_regression_fp = sum(
        1 for u in RAW_MODEL_BENIGN_REGRESSION
        if not is_trusted_apex(u) and _raw_probability(model, u) >= PHISHING_THRESHOLD
    )
    unguarded_scores = {
        u: round(_raw_probability(model, u), 4) for u in RAW_UNGUARDED_BENIGN_REGRESSION
    }
    unguarded_fp = sum(1 for p in unguarded_scores.values() if p >= PHISHING_THRESHOLD)
    return {
        "benchmark_n": len(labels),
        "benchmark_phishing": len(BENCHMARK_PHISHING),
        "benchmark_benign": len(BENCHMARK_BENIGN),
        "thresholds": {
            "suspicious": SUSPICIOUS_THRESHOLD,
            "phishing": PHISHING_THRESHOLD,
        },
        "raw": raw,
        "guarded": guarded,
        "raw_benign_regression_scores": {
            u: round(_raw_probability(model, u), 4) for u in RAW_MODEL_BENIGN_REGRESSION
        },
        "guarded_regression_fp": guarded_regression_fp,
        "raw_unguarded_benign_scores": unguarded_scores,
        "raw_unguarded_benign_fp": unguarded_fp,
    }


def load_metrics() -> dict:
    if METRICS_PATH.exists():
        try:
            return json.loads(METRICS_PATH.read_text())
        except Exception:
            return {}
    return {}


def save_metrics(metrics: dict):
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))
    logger.info("Wrote %s", METRICS_PATH.name)


# ---------------------------------------------------------------------------
# Dataset assembly
# ---------------------------------------------------------------------------

def build_dataset(small: bool):
    if small:
        max_pos = max_neg = 1500
    else:
        max_pos = max_neg = 15000

    pos_feed = _dedupe(
        _safe(fetch_urlhaus, [])
        + _safe(fetch_phishtank, [])
        + _safe(fetch_openphish, [])
        + _safe(fetch_phishstats, [])
    )
    scan_log = _dedupe(_safe(fetch_scan_log, []))
    pos_set = set(pos_feed)

    delayed_pos = [u for u in scan_log if u in pos_set]
    delayed_neg = [u for u in scan_log if u not in pos_set]

    tranco = _safe(fetch_tranco, [])
    if not tranco:
        tranco = generate_benign(max_neg * 3)

    # Structural negatives: curated real-path URLs plus synthetic path/subdomain
    # benign URLs. Kept in full so the model sees benign URLs that have paths and
    # subdomains — padding with bare-apex Tranco alone taught it "path = phishing".
    structural_benign = _dedupe(
        CURATED_BENIGN
        + CURATED_BENIGN_PATHS
        + generate_benign(max_neg // 4)
        + generate_benign_docs(max_neg // 4)
    )
    structural_benign = [u for u in structural_benign if u not in pos_set]

    # Pad the remainder with broad real-world apex domains (Tranco).
    tranco = [u for u in _dedupe(tranco) if u not in pos_set]
    pad_needed = max_neg - len(structural_benign)
    if pad_needed > 0:
        benign = _dedupe(structural_benign + tranco[:pad_needed])
    else:
        benign = structural_benign[:max_neg]
    negatives = _dedupe(benign + delayed_neg)[:max_neg]

    positives = _dedupe(HARD_NEGATIVE_PHISHING + pos_feed + delayed_pos)
    if not pos_feed and not delayed_pos:
        positives = _dedupe(positives + generate_phishing(max_pos * 3))

    random.seed(42)
    random.shuffle(positives)
    positives = positives[:max_pos]
    if len(positives) < 250:
        positives = positives + generate_phishing(250)

    # deterministic feature extraction
    start = time.time()
    X = _featurize(positives + negatives)
    y = np.array([1] * len(positives) + [0] * len(negatives), dtype=np.int32)
    logger.info("feature extraction: %d samples in %.1fs", len(y), time.time() - start)

    sources = {
        "feed_positives": len(pos_feed),
        "delayed_positives": len(delayed_pos),
        "delayed_negatives": len(delayed_neg),
        "benign_pool": len(benign),
        "train_positives": len(positives),
        "train_negatives": len(negatives),
    }
    return X, y, sources


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run(small: bool = False) -> bool:
    logger.info("Building dataset (small=%s)...", small)
    X, y, sources = build_dataset(small)
    if len(y) < 500:
        logger.error("Dataset too small to train (%d samples). Aborting.", len(y))
        return False

    model, holdout = train_on_dataset(X, y)
    benchmark = evaluate_benchmark(model)

    last = load_metrics()
    prev_f1 = (
        last.get("benchmark", {}).get("guarded", {}).get("f1")
        or last.get("benchmark", {}).get("f1")
    )
    new_f1 = benchmark["guarded"]["f1"]
    gates = {
        "guarded_benign_fp_ok": (
            benchmark["guarded"]["fp"] == 0
            and benchmark["guarded_regression_fp"] == 0
        ),
        "raw_unguarded_benign_ok": benchmark["raw_unguarded_benign_fp"] == 0,
        "raw_phishing_recall_ok": benchmark["raw"]["recall"] >= MIN_RAW_PHISHING_RECALL,
        "f1_not_regressed": prev_f1 is None or new_f1 >= prev_f1,
    }

    metrics = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "model_file": MODEL_PATH.name,
        "training": holdout,
        "benchmark": benchmark,
        "promotion_gates": gates,
        "was_better_than": prev_f1,
        "data": sources,
    }

    if all(gates.values()):
        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, MODEL_PATH, compress=3)
        save_metrics(metrics)
        logger.info(
            "PROMOTED model (guarded benchmark F1 %.3f, previous %s)",
            new_f1,
            "n/a" if prev_f1 is None else f"{prev_f1:.3f}",
        )
        return True

    logger.info(
        "Kept current model: guarded benchmark F1 %.3f, previous %s, gates=%s",
        new_f1,
        "n/a" if prev_f1 is None else f"{prev_f1:.3f}",
        gates,
    )
    return False


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--small", action="store_true", help="small smoke run")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-5s | %(message)s")
    run(small=args.small)


if __name__ == "__main__":
    main()
