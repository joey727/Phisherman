import { registry } from "./CheckerRegistry";
import { HeuristicsChecker } from "./checkers/heuristics";
import { OpenPhishChecker } from "./checkers/openPhish";
import { SafeBrowsingChecker } from "./checkers/googleSafeBrowsing";
import { URLHausChecker } from "./checkers/urlHaus";
import { PhishTankChecker } from "./checkers/phishtank";
import { WebRiskChecker } from "./checkers/googleWebRisk";
import { PhishStatsChecker } from "./checkers/phishStats";
import { ScanResult } from "./types";

// Register all checkers
registry.register(HeuristicsChecker);
registry.register(OpenPhishChecker);
registry.register(SafeBrowsingChecker);
registry.register(URLHausChecker);
registry.register(PhishTankChecker);
// registry.register(WebRiskChecker);
registry.register(PhishStatsChecker);

import redis from "./utils/redis";
import crypto from "node:crypto";

const RESULT_CACHE_TTL_SECONDS = 300; // 5 minutes
const SCAN_CACHE_HASH = "scan_results"; // single key
const SCAN_CACHE_EXPIRY_ZSET = "scan_results_expiry"; // single key
const CACHE_SAFE_RESULTS = (process.env.SCAN_CACHE_SAFE_RESULTS || "").toLowerCase() === "true";

function scanCacheId(url: string) {
  return crypto.createHash("sha256").update(url).digest("hex");
}

export async function analyzeUrl(url: string): Promise<ScanResult> {
  const id = scanCacheId(url);

  try {
    const cached = await redis.hget(SCAN_CACHE_HASH, id);
    if (cached) {
      const parsed = JSON.parse(cached as string) as { exp: number; value: ScanResult };
      if (parsed?.exp && parsed.exp > Date.now() && parsed.value) return parsed.value;
      // expired; clean up opportunistically
      await redis.hdel(SCAN_CACHE_HASH, id);
      await redis.zrem(SCAN_CACHE_EXPIRY_ZSET, id);
    }
  } catch (err) {
    console.error("Cache read error:", err);
  }

  const { checks, timing } = await registry.runAll(url);

  const totalScore = Math.min(
    100,
    checks.reduce((a, c) => a + c.score, 0)
  );

  const verdict =
    totalScore >= 70 ? "phishing" : totalScore >= 40 ? "suspicious" : "safe";

  // Collect all reasons
  const allReasons: string[] = [];
  for (const c of checks) {
    if (c.reasons && Array.isArray(c.reasons)) {
      allReasons.push(...c.reasons);
    }
    if (c.reason) {
      allReasons.push(c.reason);
    }
  }

  const result: ScanResult = {
    url,
    score: totalScore,
    verdict,
    reasons: allReasons,
    executionTimeMs: timing,
  };

  try {
    // Avoid key explosion: store scan results as fields in a single hash (plus a zset for expiry cleanup).
    // Also avoid caching "safe" results by default, since they are high-volume and low-value.
    if (CACHE_SAFE_RESULTS || result.verdict !== "safe") {
      const exp = Date.now() + RESULT_CACHE_TTL_SECONDS * 1000;
      await redis.hset(SCAN_CACHE_HASH, { [id]: JSON.stringify({ exp, value: result }) });
      await redis.zadd(SCAN_CACHE_EXPIRY_ZSET, { score: exp, member: id });
    }
  } catch (err) {
    console.error("Cache write error:", err);
  }

  return result;
}

