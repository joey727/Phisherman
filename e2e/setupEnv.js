// Runs before the e2e test module (and its imports) are evaluated.
// These env vars must be set before apiLimiter / Scanner read them at import time.
process.env.RATE_LIMIT_MAX_REQUESTS = "10000";
process.env.SCAN_CACHE_SAFE_RESULTS = "false";
process.env.ML_FEEDBACK_ENABLED = "true";