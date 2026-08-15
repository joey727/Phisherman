import { URL } from "node:url";
import { registry } from "./CheckerRegistry";
import { HeuristicsChecker } from "./checkers/heuristics";
import { OpenPhishChecker } from "./checkers/openPhish";
import { SafeBrowsingChecker } from "./checkers/googleSafeBrowsing";
import { URLHausChecker } from "./checkers/urlHaus";
import { PhishTankChecker } from "./checkers/phishtank";
import { WebRiskChecker } from "./checkers/googleWebRisk";
import { MlChecker } from "./checkers/ml";
import { PhishStatsChecker } from "./checkers/phishStats";
import { VirusTotalChecker } from "./checkers/virusTotal";
import { ScanResult, ParsedUrl, ApiKeyTier } from "./types";

// Register all checkers
registry.register(HeuristicsChecker);
registry.register(OpenPhishChecker);
registry.register(SafeBrowsingChecker);
registry.register(URLHausChecker);
registry.register(PhishTankChecker);
// registry.register(WebRiskChecker);
registry.register(PhishStatsChecker);
registry.register(VirusTotalChecker);
registry.register(MlChecker);

import redis from "./utils/redis";
import crypto from "node:crypto";

const RESULT_CACHE_TTL_SECONDS = 300; // 5 minutes
const SCAN_CACHE_HASH = "scan_results"; // single key
const SCAN_CACHE_EXPIRY_ZSET = "scan_results_expiry"; // single key
const CACHE_SAFE_RESULTS =
  (process.env.SCAN_CACHE_SAFE_RESULTS || "").toLowerCase() === "true";

// Delayed-feedback scan log (feeds ML self-training). When enabled, every scanned URL
// is recorded (URL + timestamp) so the retraining pipeline can later label URLs that
// were scored "safe" but subsequently appeared in a threat-intelligence feed.
const ML_FEEDBACK_ENABLED =
  (process.env.ML_FEEDBACK_ENABLED || "").toLowerCase() === "true";
const SCAN_LOG_KEY = "scan_log";
const SCAN_LOG_TTL_MS = 45 * 24 * 60 * 60 * 1000; // 45 days
const SCAN_LOG_MAX = 200_000;
let lastScanLogPrune = 0;

async function logScanFeedback(url: string, result: ScanResult) {
  if (!ML_FEEDBACK_ENABLED) return;
  try {
    const now = Date.now();
    await redis.zadd(SCAN_LOG_KEY, { score: now, member: url });

    // Prune old entries + cap size, at most once per hour.
    if (now - lastScanLogPrune > 60 * 60 * 1000) {
      lastScanLogPrune = now;
      await redis.zremrangebyscore(SCAN_LOG_KEY, 0, now - SCAN_LOG_TTL_MS);
      const size = Number((await redis.zcard(SCAN_LOG_KEY)) || 0);
      if (size > SCAN_LOG_MAX) {
        // Remove the oldest (lowest-score) members to stay within the cap.
        await redis.zremrangebyrank(SCAN_LOG_KEY, 0, size - SCAN_LOG_MAX - 1);
      }
    }
  } catch (err) {
    // Feedback logging is best-effort; never fail a scan because of it.
    console.error("Scan feedback log error:", err);
  }
}

function cacheProfile(enableMl: boolean): string {
  return enableMl ? "premium" : "free";
}

function scanCacheId(url: string, enableMl: boolean) {
  return crypto
    .createHash("sha256")
    .update(`${cacheProfile(enableMl)}:${url}`)
    .digest("hex");
}

function parseUrl(url: string): ParsedUrl | undefined {
  try {
    const u = new URL(url.startsWith("http") ? url : `http://${url}`);
    return {
      raw: url,
      hostname: u.hostname,
      protocol: u.protocol,
      normalized: u.href,
    };
  } catch {
    return undefined;
  }
}

export async function analyzeUrl(
  url: string,
  opts?: { tier?: ApiKeyTier; enableMl?: boolean; degraded?: boolean },
): Promise<ScanResult> {
  const tier = opts?.tier ?? "free";
  const enableMl =
    opts?.enableMl ?? (tier === "pro" || tier === "enterprise");
  // Set when an authenticated key exhausted its quota and the scan was served
  // without ML/pro enhancements. Anonymous requests are never flagged.
  const degraded = Boolean(opts?.degraded);
  const id = scanCacheId(url, enableMl);

  try {
    const cached = await redis.hget(SCAN_CACHE_HASH, id);
    if (cached) {
      const parsed = JSON.parse(cached as string) as {
        exp: number;
        value: ScanResult;
      };
      if (parsed?.exp && parsed.exp > Date.now() && parsed.value)
        return parsed.value;
      // expired; clean up opportunistically
      await redis.hdel(SCAN_CACHE_HASH, id);
      await redis.zrem(SCAN_CACHE_EXPIRY_ZSET, id);
    }
  } catch (err) {
    console.error("Cache read error:", err);
  }

  // Parse URL once upfront and pass to all checkers
  const parsedUrl = parseUrl(url);

  const { checks, timing } = await registry.runAll(url, parsedUrl, {
    tier,
    enableMl,
  });

  const vetoed = checks.some((c) => c.veto === true);

  // Established-domain veto: an established (whois age >= 365d) lexically clean
  // URL is safe-looking regardless of the lexical ML model, so drop the ML
  // checker's contribution. Feed/threat checkers keep their scores — a genuinely
  // compromised old domain hosting a phish page is still flagged by them.
  if (vetoed) {
    for (const c of checks) {
      if (c.name === "ml") c.score = 0;
    }
  }

  const totalScore = Math.min(
    100,
    checks.reduce((a, c) => a + c.score, 0),
  );

  const verdict =
    totalScore >= 70 ? "phishing" : totalScore >= 40 ? "suspicious" : "safe";

  // Collect all reasons
  const allReasons: string[] = [];
  let threatType: "phishing" | "malware" | "unwanted_software" | "mixed" | undefined;
  
  for (const c of checks) {
    const checkReasons = [];
    if (c.reasons && Array.isArray(c.reasons)) {
      checkReasons.push(...c.reasons);
      allReasons.push(...c.reasons);
    }
    if (c.reason) {
      checkReasons.push(c.reason);
      allReasons.push(c.reason);
    }
    
    // Determine threatType
    for (const r of checkReasons) {
      const lower = r.toLowerCase();
      if (lower.includes("malware")) {
        threatType = threatType && threatType !== "malware" ? "mixed" : "malware";
      } else if (lower.includes("phishing")) {
        threatType = threatType && threatType !== "phishing" ? "mixed" : "phishing";
      }
    }
  }

  if (vetoed) {
    allReasons.push("Established domain with clean URL (reputation veto)");
  }

  const result: ScanResult = {
    url,
    score: totalScore,
    verdict,
    threatType,
    reasons: allReasons,
    executionTimeMs: timing,
    tier,
    degraded,
  };

  try {
    // Avoid key explosion: store scan results as fields in a single hash (plus a zset for expiry cleanup).
    // Also avoid caching "safe" results by default, since they are high-volume and low-value.
    if (CACHE_SAFE_RESULTS || result.verdict !== "safe") {
      const exp = Date.now() + RESULT_CACHE_TTL_SECONDS * 1000;
      await redis.hset(SCAN_CACHE_HASH, {
        [id]: JSON.stringify({ exp, value: result }),
      });
      await redis.zadd(SCAN_CACHE_EXPIRY_ZSET, { score: exp, member: id });
    }
  } catch (err) {
    console.error("Cache write error:", err);
  }

  await logScanFeedback(url, result);

  return result;
}
