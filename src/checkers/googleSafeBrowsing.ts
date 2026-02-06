import axios from "axios";
import dotenv from "dotenv";
import { Checker, CheckResult } from "../types";
import { gsbCache } from "../utils/hashCache";

dotenv.config();

const CACHE_TTL = 3600; // 1 hour for valid results
const ERROR_CACHE_TTL = 900; // 15 mins for errors (e.g. billing)

export async function checkSafeBrowsing(url: string): Promise<CheckResult> {
  try {
    const cached = await gsbCache.get<CheckResult>(url);
    if (cached) return cached;
  } catch (err) { }

  try {
    const api_key = process.env.GOOGLE_SAFE_API_KEY;

    if (!api_key) {
      console.error("safe browsing key missing");
      return { score: 0 }
    }

    const r = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${api_key}`,
      {
        client: { clientId: "phish-detector", clientVersion: "1.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }
    );

    let result: CheckResult = { score: 0 };
    if (Array.isArray(r.data?.matches) && r.data.matches.length > 0) {
      result = {
        score: 50,
        reason: "Google Safe Browsing flagged this URL as dangerous",
      };
    }

    await gsbCache.set(url, result, CACHE_TTL);
    return result;
  } catch (err: any) {
    console.error("safe browsing error: ", err.response?.data || err.message);
    // Cache the error state for a shorter time to prevent retrying a broken service every scan
    await gsbCache.set(url, { score: 0 }, ERROR_CACHE_TTL);
    return { score: 0 }
  }
}

export const SafeBrowsingChecker: Checker = {
  name: "google_safe_browsing",
  check: checkSafeBrowsing,
};
