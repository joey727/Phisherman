import axios from "axios";
import dotenv from "dotenv";
import { Checker, CheckResult } from "../types";

dotenv.config();

const WEBRISK_ENDPOINT = "https://webrisk.googleapis.com/v1/uris:search";

export async function checkGoogleWebRisk(url: string): Promise<CheckResult> {
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

    if (!r.data || Object.keys(r.data).length === 0) {
      return { score: 0 };
    }

    return {
      score: 90,
      reason: "Google WebRisk threat detected",
    };
  } catch (err: any) {
    console.error("WebRisk error:", err.response?.data || err.message);
    return { score: 0 }; // fail open (non-blocking)
  }
}

export const WebRiskChecker: Checker = {
  name: "google_web_risk",
  check: checkGoogleWebRisk,
};

