# Deployment Architecture

This document describes the intended production deployment for Phisherman after the ML and malware-detection additions.

## Overview

Phisherman should be deployed as a Docker-backed API service with optional ML inference as a separate service. The Node API remains the public entry point. Redis, third-party threat APIs, and the ML service are dependencies behind that API.

```
Client
  |
  v
Render Web Service: phisherman
  |
  +--> Upstash Redis
  |      - threat feed sets
  |      - scan result cache
  |      - API checker caches
  |      - metrics counters
  |      - optional analysis queue
  |
  +--> Threat Intelligence APIs
  |      - Google Safe Browsing
  |      - Google Web Risk
  |      - VirusTotal
  |
  +--> Optional ML Service
         - FastAPI
         - XGBoost model
         - heuristic fallback if model is unavailable
```

## Services

### 1. Public API Service

Service name: `phisherman`

Runtime: Docker

Entry point: `node dist/index.js`

Public endpoints:

- `GET /health`
- `GET /metrics`
- `POST /api/check`

Responsibilities:

- Accept URL scan requests.
- Apply request backpressure and per-IP rate limiting.
- Run all checkers concurrently with per-checker timeouts.
- Cache non-safe scan results in Upstash Redis.
- Refresh feed-backed threat intelligence when `ENABLE_FEEDS=true`.
- Optionally enqueue and process background analysis work.

Recommended Render settings:

- Runtime: Docker
- Health check path: `/health`
- Auto deploy: checks passing only
- Shutdown delay: 30 seconds
- `WEB_CONCURRENCY=1` by default on small instances
- `ENABLE_CONTINUOUS_FEEDS=false` unless a dedicated larger instance is used
- `ENABLE_WORKER=false` unless queue processing is required on the same service

### 2. Optional ML Service

Service name: `phisherman-ml`

Runtime: Docker, using `ml-service/Dockerfile`

Entry point: `uvicorn app.main:app --host 0.0.0.0 --port 8080`

Private endpoints:

- `GET /health`
- `POST /predict`
- `POST /invocations`

Responsibilities:

- Load `models/phishing_xgboost.joblib` at startup.
- Score URL features with the trained model.
- Return score, label, confidence, top features, and inference latency.
- Fall back to heuristic scoring if the model artifact is missing or inference fails.

The API service calls this service only when `ML_SERVICE_URL` is configured. If the ML service is down, slow, or omitted, the Node API uses its local ML heuristic fallback.

Recommended deployment:

- Deploy as a private/internal Render web service if available.
- Set `ML_SERVICE_URL` on `phisherman` to the internal URL, for example `https://phisherman-ml.onrender.com`.
- Keep the ML service independently scalable from the API because Python ML dependencies and model memory are separate from Node request handling.

## Data Stores

### Upstash Redis

Redis is required for production.

Used for:

- Feed membership sets: URLHaus, PhishTank, OpenPhish, PhishStats.
- Bloom-backed feed acceleration where enabled.
- Hash-based scan and API result caches.
- Rate-limit counters.
- Metrics counters.
- Optional `analysis_queue` and `analysis_meta`.

Do not use a local in-memory Redis replacement in production. Rate limiting, feed caches, and scan caches are designed around shared Redis state.

## Malware Detection

Malware detection is handled through two paths:

- URLHaus feed matching flags known malicious URLs from abuse.ch.
- VirusTotal real-time lookups add engine-based malicious/suspicious counts and malware/phishing category reasons.

VirusTotal is optional. Without `VIRUSTOTAL_API_KEY`, the checker degrades silently and returns a zero score. With a key, requests are cached for one hour and protected by a local token bucket (`VT_RATE_LIMIT`, default `4` requests per minute).

## Environment Variables

Required:

| Variable | Service | Description |
|----------|---------|-------------|
| `UPSTASH_REDIS_REST_URL` | API | Upstash Redis REST URL |
| `UPSTASH_REDIS_REST_TOKEN` | API | Upstash Redis REST token |

Optional API variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `4000` | API listen port |
| `WEB_CONCURRENCY` | `1` | API worker count |
| `ENABLE_FEEDS` | `true` | Scheduled feed refreshes |
| `ENABLE_CONTINUOUS_FEEDS` | `false` | Extra short-interval feed poller |
| `ENABLE_WORKER` | `false` | Queue worker loop |
| `SCAN_CACHE_SAFE_RESULTS` | `false` | Cache safe verdicts |
| `GOOGLE_SAFE_API_KEY` | unset | Google Safe Browsing key |
| `WEBRISK_API_KEY` | unset | Google Web Risk key |
| `VIRUSTOTAL_API_KEY` | unset | VirusTotal key |
| `VT_RATE_LIMIT` | `4` | VirusTotal requests per minute per process |
| `ML_SERVICE_URL` | unset | Optional ML inference service URL |
| `RATE_LIMIT_MAX_REQUESTS` | `100` | Requests per IP per window |
| `RATE_LIMIT_WINDOW_SECONDS` | `900` | Rate-limit window |
| `MAX_CONCURRENT_REQUESTS_PER_IP` | `10` | Per-worker concurrent scan cap |
| `MAX_INFLIGHT_REQUESTS` | `200` | Per-worker global in-flight cap |

Key-management variables:

| Variable | Description |
|----------|-------------|
| `ADMIN_API_KEY` | Bearer token for full `POST/GET/PATCH/DELETE /admin/keys` management |
| `ISSUER_API_KEY` | Bearer token for the mint-only `POST /keys` endpoint (used by the self-service billing service; endpoint fails closed if unset) |

Optional ML service variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | ML service listen port if command is adjusted |
| `MODEL_PATH` | `/app/models/phishing_xgboost.joblib` | Model artifact path |
| `LOG_LEVEL` | `INFO` | ML service log level |

## Render Deployment Flow

1. GitHub Actions runs on pull requests and pushes to `main`.
2. CI installs dependencies with `npm ci`.
3. CI runs the TypeScript production build.
4. CI runs Jest with `npm run test:ci`.
5. CI builds the API Docker image.
6. Render deploys only after checks pass.
7. Render calls `/health` to verify readiness.
8. During deploy shutdown, the API drains HTTP connections and avoids restarting workers intentionally killed by shutdown.

## Production Defaults

Use these defaults for the first Render deployment:

```env
NODE_ENV=production
WEB_CONCURRENCY=1
ENABLE_FEEDS=true
ENABLE_CONTINUOUS_FEEDS=false
ENABLE_WORKER=false
SCAN_CACHE_SAFE_RESULTS=false
RATE_LIMIT_MAX_REQUESTS=100
RATE_LIMIT_WINDOW_SECONDS=900
MAX_CONCURRENT_REQUESTS_PER_IP=10
MAX_INFLIGHT_REQUESTS=200
```

Scale up conservatively:

- Increase `WEB_CONCURRENCY` only after CPU and memory headroom are confirmed.
- Keep `ENABLE_CONTINUOUS_FEEDS=false` on small instances to avoid duplicate feed work.
- Move queue processing to a dedicated worker service before enabling heavy background analysis.
- Deploy the ML service separately before setting `ML_SERVICE_URL`.

## Operational Checks

After deployment:

1. `GET /health` returns `{ "status": "ok" }`.
2. `GET /metrics` returns feed, worker, queue, and in-flight counters.
3. `POST /api/check` returns a verdict for a known safe URL.
4. Redis metrics increase after scans.
5. VirusTotal reasons appear only when `VIRUSTOTAL_API_KEY` is configured and rate limit tokens are available.
6. ML reasons appear when `ML_SERVICE_URL` is configured and the ML service is healthy.

## Failure Behavior

- Redis errors in individual caches are logged and the scan continues where possible.
- Missing Google, Web Risk, VirusTotal, or ML settings degrade gracefully.
- ML service failures trip a local circuit breaker and fall back to local heuristic scoring.
- Checker timeouts return neutral scores rather than failing the whole scan.
- Backpressure returns `503` with `Retry-After` when in-flight request limits are exceeded.
- Rate limits return `429` for per-IP request or concurrency limits.
