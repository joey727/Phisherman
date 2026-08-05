# Phisherman

A phishing URL detection API built with Node.js, Express, and TypeScript. Phisherman analyzes URLs against multiple threat-intelligence feeds, real-time API checks, DNS security validation, and heuristic rules to classify URLs as **safe**, **suspicious**, or **phishing**.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [ML and Malware Setup](#ml-and-malware-setup)
- [Project Structure](#project-structure)
- [Development](#development)
- [Performance](#performance)
- [License](#license)

---

## Features

### Multi-Source Threat Intelligence

Phisherman cross-references URLs against multiple independent sources to maximize detection accuracy:

| Source | Type | Update Interval |
|--------|------|----------------|
| URLHaus | Streaming CSV feed (abuse.ch) | 5 minutes |
| PhishTank | Streaming CSV.GZ feed | 1 hour |
| OpenPhish | Text feed (community) | 15 minutes |
| PhishStats | JSON API (last 20k entries) | 90 minutes |
| Google Safe Browsing | Real-time API (v4) | Per-request (cached 1h) |
| Google Web Risk | Real-time API (v1) | Per-request (cached 1h) |
| VirusTotal | Real-time malware/phishing reputation API | Per-request (cached 1h) |

### Heuristic Analysis

Detects common phishing patterns:
- Overly long URLs (>200 characters)
- `@` sign in URL (credential-harvesting trick)
- Suspicious keywords (verify, update, secure, login, support, account)
- Hyphens in domain name
- Missing HTTPS
- Recently registered domains (<90 days via WHOIS)
- Punycode/IDN homograph indicators
- Data URI evasion patterns
- URL shorteners and excessive subdomain depth

### ML and Malware Detection

Phisherman includes two malware-aware additions:

- A VirusTotal checker that scores malicious and suspicious engine detections, adds malware/phishing category reasons, caches results, and respects the free-tier request rate with `VT_RATE_LIMIT`.
- An optional FastAPI ML service in `ml-service/` that loads an XGBoost model and exposes `/predict`. The Node API calls it when `ML_SERVICE_URL` is set and falls back to local heuristic ML scoring if the service is unavailable.

### Network Security

Hardened protections against server-side request forgery (SSRF) and DNS rebinding:
- Blocks private IP ranges (10.x, 127.x, 172.16-31.x, 192.168.x, 169.254.x)
- Blocks IPv6 private/loopback/link-local addresses
- DNS rebinding detection via parallel dual-resolution verification
- Rejects malformed or unsafe hostnames

### Machine-Learning Detection

An optional XGBoost classifier runs in a separate `ml-service` (FastAPI) and adds a 41-feature signal on top of the rule-based checkers:
- Feature vector covers URL length and entropy, hostname/digit/TLD properties, suspicious keywords, brand-impersonation patterns, and domain age.
- The Node app calls `POST {ML_SERVICE_URL}/predict` via `src/utils/ml.ts`; results surface as `ML:` reasons. If the service is unreachable the scanner degrades to local heuristics.
- **Trusted-apex guard:** URLs hosted on an official brand/popular apex (`TRUSTED_APEX` in `ml-service/app/features.py`) are treated as benign — brand-impersonation and suspicious-keyword features are suppressed and `predict()` short-circuits to a safe verdict. Phishing lookalikes live on *different* apexes (`paypal-secure-verify.tk`), so they are unaffected: `https://www.paypal.com/signin` scores 0 while `http://paypal-secure-verify.tk/login/account.php` scores 100.

### Caching Architecture

All caching is centralized through Upstash Redis (HTTP-based), designed to minimize both key explosion and round-trip latency:
- Threat feed data stored in Redis Sets for O(1) lookups
- API results (Safe Browsing, Web Risk, DNS) cached in hash-based structures with per-entry TTL
- Scan results cached for 5 minutes (non-safe verdicts by default)
- WHOIS data cached for 24 hours
- All compound Redis operations use pipelines to minimize HTTP round-trips

### Rate Limiting

IP-based rate limiting (100 requests per 15-minute window) applied to the scan endpoint. Uses pipelined Redis operations for minimal overhead.

---

## Architecture

```
Request --> Express --> Rate Limiter --> Scanner
                                           |
                                     Parse URL once
                                           |
                              +------------+------------+
                              |            |            |
                         Heuristics   Feed Lookups   API Checks
                         (+ WHOIS)   (URLHaus,      (Safe Browsing,
                          (+ DNS)    PhishTank,      Web Risk,
                                     OpenPhish,
                                     PhishStats)
                              +------------+------------+
                                           |
                      ML checker (if ML_SERVICE_URL set:
                      POST /predict -> ml-service)
                                           |
                                    Score Aggregation
                                    (sum, capped 100)
                                           |
                                     Verdict Logic
                                  >=70: phishing
                                  >=40: suspicious
                                   <40: safe
                                           |
                                     Cache Result
                                           |
                                      Response
```

All checkers run concurrently with a 2.5-second timeout per checker. Feed data is loaded into Redis at startup and refreshed on configurable intervals by the CacheManager (all feeds refresh in parallel).

---

## Getting Started

### Prerequisites

- Node.js 20+
- An Upstash Redis instance (free tier works)
- Google Safe Browsing API key (optional)
- Google Web Risk API key (optional)

### Installation

```bash
git clone https://github.com/joey727/phisherman.git
cd phisherman
npm install
```

### Environment Variables

Create a `.env` file in the project root:

```env
# Required -- Upstash Redis
UPSTASH_REDIS_REST_URL=https://your-instance.upstash.io
UPSTASH_REDIS_REST_TOKEN=your-token

# Optional -- Google APIs (checkers degrade gracefully without these)
GOOGLE_SAFE_API_KEY=your-key
WEBRISK_API_KEY=your-key

# Optional -- malware and ML checks
VIRUSTOTAL_API_KEY=your-key
VT_RATE_LIMIT=4
ML_SERVICE_URL=http://localhost:8080

# Optional -- PhishTank custom URL
PHISHTANK_API_URL=https://data.phishtank.com/data/online-valid.csv.gz

# Optional -- ML service (enables the ML checker)
ML_SERVICE_URL=https://ml-service.example.onrender.com

# Optional -- Log scans for ML retraining feedback
ML_FEEDBACK_ENABLED=false

# Optional -- Server
PORT=4000

# Optional -- Cache "safe" scan results (default: false, to save Redis space)
SCAN_CACHE_SAFE_RESULTS=false
```

### Running Locally

```bash
# Development (auto-reload)
npm run dev

# Production
npm run build
npm start
```

---

## API Reference

### POST /api/check

Analyze a URL for phishing indicators.

**Request:**

```json
{
  "url": "https://suspicious-site.com/login"
}
```

**Response:**

```json
{
  "url": "https://suspicious-site.com/login",
  "score": 73,
  "verdict": "phishing",
  "threatType": "phishing",
  "reasons": [
    "Contains suspicious keywords",
    "Domain is recently created (<90 days)",
    "Hyphens in domain"
  ],
  "executionTimeMs": {
    "heuristics": 245,
    "openphish": 12,
    "google_safe_browsing": 189,
    "urlhaus": 8,
    "phishtank": 6,
    "phishstats": 11
  }
}
```

**Scoring:**
- `>= 70` -- Verdict: **phishing**
- `>= 40` -- Verdict: **suspicious**
- `< 40` -- Verdict: **safe**

**Rate Limiting:**

100 requests per IP per 15-minute window. Returns `429 Too Many Requests` when exceeded.

---

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `UPSTASH_REDIS_REST_URL` | Yes | -- | Upstash Redis REST endpoint |
| `UPSTASH_REDIS_REST_TOKEN` | Yes | -- | Upstash Redis auth token |
| `GOOGLE_SAFE_API_KEY` | No | -- | Google Safe Browsing v4 API key |
| `WEBRISK_API_KEY` | No | -- | Google Web Risk v1 API key |
| `VIRUSTOTAL_API_KEY` | No | -- | VirusTotal API key for malware/phishing reputation |
| `VT_RATE_LIMIT` | No | 4 | VirusTotal requests per minute per API process |
| `ML_SERVICE_URL` | No | -- | Optional FastAPI ML inference service URL |
| `PHISHTANK_API_URL` | No | CSV.GZ feed | Custom PhishTank data URL |
| `PHISHSTATS_API_KEY` | No | -- | Optional PhishStats `psk_*` API key; sent as `X-API-Key` to lift the anonymous 50 req/day/IP quota |
| `PHISHSTATS_MAX_PAGES` | No | 3 (or 10 with key) | Max feed pages (100 rows each) fetched per PhishStats refresh, bounded to respect API rate limits |
| `PORT` | No | 4000 | Server listen port |
| `SCAN_CACHE_SAFE_RESULTS` | No | false | Cache scan results with "safe" verdict |
| `WEB_CONCURRENCY` | No | 1 | Number of HTTP worker processes |
| `ENABLE_FEEDS` | No | true | Enable scheduled threat-feed refreshes |
| `ENABLE_CONTINUOUS_FEEDS` | No | false | Enable the additional short-interval feed poller |
| `ENABLE_WORKER` | No | false | Enable queued background URL analysis |
| `RATE_LIMIT_MAX_REQUESTS` | No | 100 | Requests per IP per rate-limit window |
| `RATE_LIMIT_WINDOW_SECONDS` | No | 900 | Rate-limit window size |
| `MAX_CONCURRENT_REQUESTS_PER_IP` | No | 10 | Per-worker concurrent scan cap per IP |
| `MAX_INFLIGHT_REQUESTS` | No | 200 | Per-worker global in-flight request cap |
| `ML_SERVICE_URL` | No | -- | Base URL of the ML service (e.g. `https://ml-service-xxxx.onrender.com`); enables the ML checker |
| `ML_FEEDBACK_ENABLED` | No | false | Log scanned URLs to Redis `scan_log` for ML retraining feedback |

---

## Deployment

### Docker

The project uses a multi-stage Docker build to keep the production image lean (no dev dependencies):

```bash
docker build -t phisherman .
docker run -p 4000:4000 --env-file .env phisherman
```

### Render

The repository includes `render.yaml` (a Render blueprint at the repo root) declaring **two** Docker web services:

| Service | Dockerfile | Health check | Notes |
|---------|-----------|--------------|-------|
| `phisherman` | `./Dockerfile` (Node 20) | `/health` | Main API; listens on Render's injected `$PORT` |
| `ml-service` | `./ml-service/Dockerfile` (Python 3.12) | `/health` | FastAPI classifier; `dockerCommand` starts uvicorn on `$PORT` |

Blueprint highlights:
- `healthCheckPath: /health` enables HTTP readiness checks on both services (must listen on Render's `$PORT`, not a hardcoded port).
- `autoDeployTrigger: checksPass` waits for GitHub CI before deploying.
- `maxShutdownDelaySeconds: 30` gives the app time to drain during zero-downtime deploys.
- Secrets (Upstash, Google, WebRisk, VirusTotal) are declared with `sync: false` and must be provided in the Render dashboard.
- The Node service's `ML_SERVICE_URL` points at the deployed `ml-service` URL so the ML checker is wired end to end.

Default Render-oriented settings use one HTTP worker (`WEB_CONCURRENCY=1`), scheduled feed refreshes, and no continuous poller or queue worker unless explicitly enabled.

See [deployment.md](deployment.md) for the full production architecture, including the optional ML service and malware intelligence setup.

---

## ML and Malware Setup

### VirusTotal

VirusTotal support is optional. Add `VIRUSTOTAL_API_KEY` to enable real-time malware/phishing reputation checks:

```env
VIRUSTOTAL_API_KEY=your-key
VT_RATE_LIMIT=4
```

The checker caches results for one hour, caches 404/error states for 15 minutes, and skips requests once the local token bucket is exhausted instead of slowing the scan path.

### ML Service

The ML service is a separate FastAPI app under `ml-service/`. It loads `ml-service/models/phishing_xgboost.joblib`, exposes `/health` and `/predict`, and falls back to heuristic scoring when the model is unavailable.

Run locally:

```bash
cd ml-service
docker compose up --build
```

Then point the Node API at it:

```env
ML_SERVICE_URL=http://localhost:8080
```

For production, deploy the ML service separately from the Node API and set `ML_SERVICE_URL` on the API service to the ML service URL. Keeping the ML service separate avoids coupling Python dependency and model memory usage to the public API process.

### Docker Compose (example)

```yaml
services:
  phisherman:
    build: .
    ports:
      - "4000:4000"
    env_file: .env
    restart: unless-stopped
```

---

## Project Structure

```
src/
  app.ts                # Express app factory, routes, middleware
  index.ts              # Process startup, clustering, background tasks
  Scanner.ts            # Orchestrates all checkers, caches results
  CheckerRegistry.ts    # Registry pattern for checker plugins
  CacheManager.ts       # Background feed refresh scheduler
  types.ts              # Shared TypeScript interfaces
  checkers/
    heuristics.ts       # URL pattern analysis + WHOIS + DNS
    openPhish.ts        # OpenPhish feed checker
    googleSafeBrowsing.ts  # Google Safe Browsing API
    googleWebRisk.ts    # Google Web Risk API
    virusTotal.ts       # VirusTotal malware/phishing reputation API
    urlHaus.ts          # URLHaus feed checker
    phishtank.ts        # PhishTank feed checker
    phishStats.ts       # PhishStats API checker
  utils/
    redis.ts            # Upstash Redis client
    hashCache.ts        # Hash-based cache with per-entry TTL
    network.ts          # DNS resolution + SSRF protection
    ml.ts               # ML checker client (calls ML_SERVICE_URL /predict)
  middleware/
    ratelimit.ts        # IP-based rate limiter
__tests__/              # Jest test suite
e2e/                    # End-to-end test suite (scan.e2e.ts)
scripts/
  benchmark.ts          # Performance benchmarking script
ml-service/             # ML classification service (FastAPI + XGBoost)
  app/
    main.py             # FastAPI app: /predict, /health, /ping, /invocations
    model.py            # Model loading, inference, trusted-apex guard, fallback
    features.py         # 41-feature extraction + TRUSTED_APEX
    schemas.py          # Request/response models
  training/
    pipeline.py         # Feed ingestion, training, safe-promotion gate
    train.py            # Shared training utilities
  models/               # phishing_xgboost.joblib + metrics.json
  Dockerfile
```

---

## Development

### Testing

```bash
npm test
npm run test:ci
```

CI (`.github/workflows/ci.yml`) runs the Node build + unit tests **and** an `ml-service-test` job that installs the Python deps, loads the committed model, hits `/health` and `/predict`, then builds the ML Docker image — so a broken model or API never ships.

### End-to-End Testing

```bash
npm run test:e2e
```

Runs a real end-to-end suite (`e2e/scan.e2e.ts`) against the live pipeline — no mocking of the app, Scanner, registry, or checkers. It boots the actual Express server and exercises HTTP → backpressure → rate limiting → validation → `analyzeUrl` → Redis result cache → all checkers → scoring → verdict against a matrix of safe/suspicious/phishing URLs.

Requirements and caveats:

- Needs live Upstash Redis credentials in `.env` (the suite clears `scan_results`, `whois_data`, and `ratelimit:*` keys before and after, but run it against a dev instance if you want to avoid touching shared data).
- Requires outbound network access (DNS, external threat-intelligence APIs, optional ML service).
- Only the `whois-json` library is mocked, because it is pure-ESM and Jest's CJS loader cannot import it — the WHOIS port-43 lookup itself is a network boundary, so the rest of the pipeline stays real and deterministic.
- If `ML_SERVICE_URL` is reachable, the ML checker returns `ML:` reasons; otherwise it degrades to local heuristics. Either way the suite passes.
- Intentionally **excluded from CI** (`npm run test:ci` / the `build-and-test` job) because it requires real Redis and network. Run it locally or add Redis secrets to CI if you want it gated there.

### ML Service (ml-service)

The `ml-service/` directory is a standalone FastAPI + XGBoost classifier deployed as its own Render service. The Node app calls it over HTTP when `ML_SERVICE_URL` is set.

**Endpoints:**
- `POST /predict` — `{ "url": "...", "meta": {...} }` → `{ score, label, confidence, top_features, inference_time_ms }`. Scores are 0-100; `safe`/`suspicious`/`phishing` labels use the same thresholds as the Node app.
- `GET /health` — reports `model_loaded` status.
- `GET /ping`, `POST /invocations` — SageMaker-compatible health/inference aliases.

**Run locally:**
```bash
cd ml-service
python3 -m venv .venv && source .venv/bin/activate   # needs `brew install libomp` on macOS
pip install -r requirements.txt
uvicorn app.main:app --port 8080
curl -X POST localhost:8080/predict -H 'Content-Type: application/json' \
  -d '{"url":"http://paypal-secure-verify.tk/login/account.php","meta":{}}'
```

**Model artifact:** `ml-service/models/phishing_xgboost.joblib` is committed (Dockerfile copies it in); retrain/promote via the pipeline below.

### Self-Training Data Pipeline

The ML model can retrain itself (safely) on an automated schedule. See `ml-service/training/pipeline.py`.

**How it collects data (never from the model's own verdicts):**

- **Positives** — public threat-intel feeds pulled directly by the pipeline: URLHaus, PhishTank, OpenPhish, PhishStats.
- **Delayed positives (active learning)** — the Node app can log every scanned URL to a Redis ZSET `scan_log` (`src/Scanner.ts`, gated by `ML_FEEDBACK_ENABLED`, 45-day retention, capped at 200k). If a URL that was scanned earlier ends up in a feed later, it becomes a high-value positive (an earlier under-detection).
- **Negatives** — a benign corpus (Tranco top list) plus `scan_log` URLs not present in any feed.
- **Fallback** — synthetic benign/phishing patterns if a source is unreachable, so the job never crashes on a flaky feed.

**Safe promotion:** before writing `ml-service/models/phishing_xgboost.joblib`, the new model is evaluated on a fixed benchmark set and only replaces the current model if its benchmark F1 is `>=` the last-promoted model's. A worse model is never deployed. Runs and metrics are recorded in `ml-service/models/metrics.json`.

**Weekly orchestration** (`.github/workflows/retrain.yml`, cron `0 3 * * 1`):
1. Runner fetches data → trains → evaluates → promotes only on improvement.
2. If promoted, the model + `metrics.json` are committed to `main` via a PAT.
3. That push triggers CI (`checksPass`) → Render rebuilds the `ml-service` image with the new model.

**Required GitHub secrets:** `GH_PAT` (contents + actions write — the default `GITHUB_TOKEN` cannot push to `main` or re-trigger workflows), `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN` (only needed to read the delayed-feedback `scan_log`). The delayed-feedback phase is supported but you can run the feed-based core loop without the Redis secrets.

**Manual run:** `cd ml-service && pip install -r requirements.txt && python -m training.pipeline --small` (use a `.venv`; needs `brew install libomp` on macOS).

### Building

```bash
npm run build    # Compiles TypeScript to dist/
```

### Benchmarking

```bash
npx ts-node scripts/benchmark.ts
```

### Adding a New Checker

1. Create a new file in `src/checkers/` implementing the `Checker` interface:

```typescript
import { Checker, CheckResult, ParsedUrl } from "../types";

export async function checkMySource(url: string, parsed?: ParsedUrl): Promise<CheckResult> {
  // Use parsed.hostname instead of re-parsing the URL
  // Return { score: 0-100, reason?: string }
}

export const MySourceChecker: Checker = {
  name: "my_source",
  check: checkMySource,
};
```

2. Register it in `src/Scanner.ts`:

```typescript
import { MySourceChecker } from "./checkers/mySource";
registry.register(MySourceChecker);
```

3. If the checker needs a background feed, add a load function and register it in `src/index.ts`:

```typescript
cacheManager.addTask("my_source", loadMySource);
```

---

## Performance

Key optimizations in this codebase:

- **Parallel feed loading** -- All threat feeds refresh concurrently at startup and on schedule, so total refresh time equals the slowest feed rather than the sum.
- **Concurrent checker execution** -- All checkers run in parallel via `Promise.all` with per-checker 2.5s timeouts.
- **Single URL parse per request** -- The URL is parsed once in the Scanner and the result is passed to all checkers, avoiding redundant parsing.
- **Pipelined Redis operations** -- All compound cache operations (set+expire, delete+cleanup) use Upstash pipelines to batch multiple commands into single HTTP round-trips.
- **Parallel DNS resolution** -- Initial DNS resolution and rebinding detection run concurrently, halving DNS latency for uncached hosts.
- **Streaming feed ingestion** -- Large feeds (URLHaus, PhishTank) are processed as streams with batched Redis writes and event-loop yields to avoid blocking.
- **Scoped rate limiting** -- Rate limiter only applies to the scan endpoint, avoiding unnecessary Redis overhead on other routes.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
