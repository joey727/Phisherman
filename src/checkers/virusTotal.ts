import axios from "axios";
import crypto from "node:crypto";
import { Checker, CheckResult, ParsedUrl } from "../types";
import { HashCache } from "../utils/hashCache";

const VT_CACHE = new HashCache("vt_cache", 3600); // 1 hour cache
const ERROR_CACHE_TTL = 900; // 15 min for errors

// ---------------------------------------------------------------------------
// Token bucket rate limiter — respects VirusTotal free tier (4 req/min)
// ---------------------------------------------------------------------------

const VT_RATE_LIMIT = Number(process.env.VT_RATE_LIMIT) || 4;
const VT_RATE_WINDOW_MS = 60_000; // 1 minute

let vtTokens = VT_RATE_LIMIT;
let vtLastRefill = Date.now();

function vtAcquireToken(): boolean {
  const now = Date.now();
  const elapsed = now - vtLastRefill;

  // Refill tokens based on elapsed time
  if (elapsed >= VT_RATE_WINDOW_MS) {
    vtTokens = VT_RATE_LIMIT;
    vtLastRefill = now;
  } else {
    // Partial refill
    const refill = Math.floor((elapsed / VT_RATE_WINDOW_MS) * VT_RATE_LIMIT);
    if (refill > 0) {
      vtTokens = Math.min(VT_RATE_LIMIT, vtTokens + refill);
      vtLastRefill = now;
    }
  }

  if (vtTokens > 0) {
    vtTokens--;
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// URL ID for VirusTotal API (base64url of the URL, no padding)
// ---------------------------------------------------------------------------

function vtUrlId(url: string): string {
  return Buffer.from(url).toString("base64url");
}

// ---------------------------------------------------------------------------
// Checker
// ---------------------------------------------------------------------------

export async function checkVirusTotal(
  url: string,
  _parsed?: ParsedUrl,
): Promise<CheckResult> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  // Graceful degradation: no API key → skip silently
  if (!apiKey) {
    return { score: 0 };
  }

  // Check cache first
  try {
    const cached = await VT_CACHE.get<CheckResult>(url);
    if (cached) return cached;
  } catch {}

  // Rate limit check
  if (!vtAcquireToken()) {
    // Exceeded rate limit — skip this check rather than blocking
    return { score: 0, reason: "VirusTotal rate limit — skipped" };
  }

  try {
    const urlId = vtUrlId(url);
    const response = await axios.get(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
      {
        headers: {
          "x-apikey": apiKey,
          Accept: "application/json",
        },
        timeout: 5000,
      },
    );

    const stats = response.data?.data?.attributes?.last_analysis_stats;
    if (!stats) {
      await VT_CACHE.set(url, { score: 0 }, ERROR_CACHE_TTL);
      return { score: 0 };
    }

    const malicious = Number(stats.malicious) || 0;
    const suspicious = Number(stats.suspicious) || 0;

    const score = Math.min(100, malicious * 10 + suspicious * 5);
    const reasons: string[] = [];

    if (malicious > 0) {
      reasons.push(
        `VirusTotal: ${malicious} engine(s) flagged as malicious`,
      );
    }
    if (suspicious > 0) {
      reasons.push(
        `VirusTotal: ${suspicious} engine(s) flagged as suspicious`,
      );
    }

    // Determine threat category from VirusTotal categories
    const categories = response.data?.data?.attributes?.categories || {};
    const catValues = Object.values(categories).map((v: any) =>
      String(v).toLowerCase(),
    );
    let threatReason = "";
    if (catValues.some((c) => c.includes("malware") || c.includes("malicious"))) {
      threatReason = "VirusTotal category: malware";
    } else if (catValues.some((c) => c.includes("phishing"))) {
      threatReason = "VirusTotal category: phishing";
    }
    if (threatReason) reasons.push(threatReason);

    const result: CheckResult = {
      score,
      reasons: reasons.length > 0 ? reasons : undefined,
      reason: reasons.length === 1 ? reasons[0] : undefined,
    };

    await VT_CACHE.set(url, result, 3600);
    return result;
  } catch (err: any) {
    // 404 = URL not found in VT (not scanned yet) — not an error
    if (err.response?.status === 404) {
      await VT_CACHE.set(url, { score: 0 }, ERROR_CACHE_TTL);
      return { score: 0 };
    }

    console.error(
      "VirusTotal check error:",
      err.response?.status || err.message,
    );
    await VT_CACHE.set(url, { score: 0 }, ERROR_CACHE_TTL);
    return { score: 0 };
  }
}

export const VirusTotalChecker: Checker = {
  name: "virustotal",
  check: checkVirusTotal,
};
