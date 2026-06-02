import tldts from "tldts";
import crypto from "node:crypto";
import axios from "axios";

// ---------------------------------------------------------------------------
// Circuit breaker for ML service
// ---------------------------------------------------------------------------

const CIRCUIT_BREAKER_THRESHOLD = 5; // failures before opening
const CIRCUIT_BREAKER_RESET_MS = 30_000; // 30s before half-open retry
const ML_TIMEOUT_MS = 2000; // 2s max for ML call

let circuitFailures = 0;
let circuitOpenedAt = 0;
let circuitState: "closed" | "open" | "half-open" = "closed";

function isCircuitOpen(): boolean {
  if (circuitState === "closed") return false;
  if (circuitState === "open") {
    // Check if enough time has passed to try again
    if (Date.now() - circuitOpenedAt > CIRCUIT_BREAKER_RESET_MS) {
      circuitState = "half-open";
      return false; // allow one request through
    }
    return true;
  }
  return false; // half-open: let it through
}

function recordSuccess() {
  circuitFailures = 0;
  circuitState = "closed";
}

function recordFailure() {
  circuitFailures++;
  if (circuitFailures >= CIRCUIT_BREAKER_THRESHOLD) {
    circuitState = "open";
    circuitOpenedAt = Date.now();
    console.warn(
      `ML circuit breaker OPEN after ${circuitFailures} failures. Will retry in ${CIRCUIT_BREAKER_RESET_MS / 1000}s.`,
    );
  }
}

// ---------------------------------------------------------------------------
// Local heuristic fallback (original logic preserved)
// ---------------------------------------------------------------------------

function hostnameEntropy(hostname: string) {
  const s = hostname.replace(/\./g, "");
  const freqs: Record<string, number> = {};
  for (const c of s) freqs[c] = (freqs[c] || 0) + 1;
  const probs = Object.values(freqs).map((v) => v / s.length);
  const H = -probs.reduce((a, p) => a + (p > 0 ? p * Math.log2(p) : 0), 0);
  return H;
}

function localFallbackScore(
  url: string,
  meta: any = {},
): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  let score = 0;

  try {
    const parsed = tldts.parse(url);
    const hostname = parsed.hostname || "";

    // entropy: suspicious if very high randomness
    const ent = hostnameEntropy(hostname || "");
    if (ent > 4.5) {
      score += 12;
      reasons.push("High hostname entropy");
    }

    // too many digits
    const digitCount = (hostname.match(/\d/g) || []).length;
    if (digitCount > 3) {
      score += 8;
      reasons.push("Many digits in hostname");
    }

    // long URL
    if (url.length > 180) {
      score += 6;
      reasons.push("Long URL");
    }

    // suspicious tld
    const suspectTlds = ["tk", "ml", "cf", "ga"];
    if (suspectTlds.includes(parsed.publicSuffix || "")) {
      score += 8;
      reasons.push("Suspicious TLD");
    }

    // whois age if present in meta
    const age =
      meta?.result?.meta?.whois?.domainAgeDays ||
      meta?.meta?.domainAgeDays ||
      meta?.whois?.domainAgeDays;
    if (typeof age === "number") {
      if (age < 30) {
        score += 12;
        reasons.push("Very new domain");
      } else if (age < 180) {
        score += 6;
        reasons.push("Recently created domain");
      }
    }

    // heuristic signals from prior analysis
    const priorScore = meta?.result?.score || 0;
    if (priorScore >= 40) {
      score += Math.min(30, priorScore / 2);
      reasons.push("Existing checkers flagged URL");
    }
  } catch (err) {
    // fail-open: don't crash
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, reasons };
}

// ---------------------------------------------------------------------------
// Main scoring function
// ---------------------------------------------------------------------------

export async function scoreUrlMl(
  url: string,
  meta: any = {},
): Promise<{ score: number; reasons: string[] }> {
  const mlServiceUrl = process.env.ML_SERVICE_URL;

  // If ML service URL is configured and circuit is not open, try remote ML
  if (mlServiceUrl && !isCircuitOpen()) {
    try {
      const response = await axios.post(
        `${mlServiceUrl}/predict`,
        {
          url,
          meta: {
            domain_age_days: meta?.meta?.domainAgeDays ?? meta?.whois?.domainAgeDays ?? -1,
            prior_score: meta?.result?.score ?? 0,
            prior_checker_count: meta?.result?.reasons?.length ?? 0,
          },
        },
        {
          timeout: ML_TIMEOUT_MS,
          headers: { "Content-Type": "application/json" },
        },
      );

      const data = response.data;
      recordSuccess();

      const reasons: string[] = [];
      if (data.top_features && Array.isArray(data.top_features)) {
        for (const f of data.top_features) {
          reasons.push(`ML: ${f.replace(/_/g, " ")}`);
        }
      }
      if (data.label && data.label !== "safe") {
        reasons.push(`ML model: ${data.label} (confidence: ${(data.confidence * 100).toFixed(0)}%)`);
      }

      return {
        score: Math.max(0, Math.min(100, data.score ?? 0)),
        reasons,
      };
    } catch (err: any) {
      recordFailure();
      const detail = err.code === "ECONNABORTED" ? "timeout" : err.message;
      console.warn(`ML service call failed (${detail}), using local fallback`);
    }
  }

  // Fallback to local heuristic scoring
  return localFallbackScore(url, meta);
}
