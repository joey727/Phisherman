import axios from "axios";
import dotenv from "dotenv";
import { Checker, CheckResult } from "../types";

dotenv.config();

const WEBRISK_ENDPOINT = "https://webrisk.googleapis.com/v1/uris:search";

import redis from "../utils/redis";

const CACHE_KEY_PREFIX = "gwr_cache:";
const CACHE_TTL = 3600; // 1 hour
const ERROR_CACHE_TTL = 900; // 15 mins

export async function checkGoogleWebRisk(url: string): Promise<CheckResult> {
  const cacheKey = `${CACHE_KEY_PREFIX}${url}`;

  try {
    const cached = await redis.get(cacheKey);
    if (cached) return (typeof cached === "string" ? JSON.parse(cached) : cached) as CheckResult;
  } catch (err) { }

  const apiKey = process.env.WEBRISK_API_KEY;

  if (!apiKey) {
    console.error("Missing WEBRISK_API_KEY in environment variables");
    return { score: 0 };
  }

  try {
    const r = await axios.get(WEBRISK_ENDPOINT, {
      params: {
        uri: url,
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
        key: apiKey,
      },
      paramsSerializer: (params: Record<string, string>) =>
        `uri=${encodeURIComponent(params.uri)}&key=${params.key}` +
        `&threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE`,
      timeout: 6000,
    });

    let result: CheckResult = { score: 0 };
    if (r.data && Object.keys(r.data).length > 0) {
      result = {
        score: 90,
        reason: "Google WebRisk threat detected",
      };
    }

    await redis.setex(cacheKey, CACHE_TTL, JSON.stringify(result));
    return result;
  } catch (err: any) {
    console.error("WebRisk error:", err.response?.data || err.message);
    await redis.setex(cacheKey, ERROR_CACHE_TTL, JSON.stringify({ score: 0 }));
    return { score: 0 }; // fail open (non-blocking)
  }
}

export const WebRiskChecker: Checker = {
  name: "google_web_risk",
  check: checkGoogleWebRisk,
};

