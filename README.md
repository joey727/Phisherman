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
- [Project Structure](#project-structure)
- [Development](#development)
- [Performance](#performance)
- [License](#license)

---

## Features

### Multi-Source Threat Intelligence

Phisherman cross-references URLs against six independent sources to maximize detection accuracy:

| Source | Type | Update Interval |
|--------|------|----------------|
| URLHaus | Streaming CSV feed (abuse.ch) | 5 minutes |
| PhishTank | Streaming CSV.GZ feed | 1 hour |
| OpenPhish | Text feed (community) | 15 minutes |
| PhishStats | JSON API (last 20k entries) | 90 minutes |
| Google Safe Browsing | Real-time API (v4) | Per-request (cached 1h) |
| Google Web Risk | Real-time API (v1) | Per-request (cached 1h) |

### Heuristic Analysis

Detects common phishing patterns:
- Overly long URLs (>200 characters)
- `@` sign in URL (credential-harvesting trick)
- Suspicious keywords (verify, update, secure, login, support, account)
- Hyphens in domain name
- Missing HTTPS
- Recently registered domains (<90 days via WHOIS)

### Network Security

Hardened protections against server-side request forgery (SSRF) and DNS rebinding:
- Blocks private IP ranges (10.x, 127.x, 172.16-31.x, 192.168.x, 169.254.x)
- Blocks IPv6 private/loopback/link-local addresses
- DNS rebinding detection via parallel dual-resolution verification
- Rejects malformed or unsafe hostnames

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
                          (+ DNS)    PhishTank,      Web Risk)
                                     OpenPhish,
                                     PhishStats)
                              |            |            |
                              +------------+------------+
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

# Optional -- PhishTank custom URL
PHISHTANK_API_URL=https://data.phishtank.com/data/online-valid.csv.gz

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
| `PHISHTANK_API_URL` | No | CSV.GZ feed | Custom PhishTank data URL |
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

---

## Deployment

### Docker

The project uses a multi-stage Docker build to keep the production image lean (no dev dependencies):

```bash
docker build -t phisherman .
docker run -p 4000:4000 --env-file .env phisherman
```

### Render

The repository includes `render.yaml` for Docker-based Render deployment:

- `healthCheckPath: /health` enables HTTP readiness checks.
- `autoDeployTrigger: checksPass` waits for GitHub CI before deploying.
- `maxShutdownDelaySeconds: 30` gives the app time to drain during zero-downtime deploys.
- Secrets such as Upstash, Google, and VirusTotal API keys are declared with `sync: false` and must be provided in Render.

Default Render-oriented settings use one HTTP worker (`WEB_CONCURRENCY=1`), scheduled feed refreshes, and no continuous poller or queue worker unless explicitly enabled.

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
    urlHaus.ts          # URLHaus feed checker
    phishtank.ts        # PhishTank feed checker
    phishStats.ts       # PhishStats API checker
  utils/
    redis.ts            # Upstash Redis client
    hashCache.ts        # Hash-based cache with per-entry TTL
    network.ts          # DNS resolution + SSRF protection
  middleware/
    ratelimit.ts        # IP-based rate limiter
__tests__/              # Jest test suite
scripts/
  benchmark.ts          # Performance benchmarking script
```

---

## Development

### Testing

```bash
npm test
npm run test:ci
```

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
