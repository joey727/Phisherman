import axios from "axios";
import dotenv from "dotenv";
import { URL } from "node:url";
import redis from "../utils/redis";
import pako from "pako";

dotenv.config();

const REDIS_KEY_URLS = "phishtank_urls";
// const REDIS_KEY_HOSTS = "phishtank_hosts";
const REDIS_KEY_LAST_UPDATE = "phishtank_last_update";
const REDIS_KEY_LAST_FAIL = "phishtank_last_fail";
const FAIL_COOLDOWN_MS = 15 * 60 * 1000; // back off for 15 minutes after a failed fetch
const MAX_FEED_BYTES = 20 * 1024 * 1024; // 20MB max for 512MB server (leaves room for decompression + processing)
const PROCESSING_BATCH_SIZE = 500; // Process URLs in smaller batches to reduce memory spikes

const DEFAULT_PHISHTANK_URLS = [
  "https://data.phishtank.com/data/online-valid.json.gz",
  "https://data.phishtank.com/data/online-valid.json",
];

export async function loadPhishTank() {
  try {
    const lastUpdate = await redis.get(REDIS_KEY_LAST_UPDATE);
    const cacheExpired = !lastUpdate || (Date.now() - Number(lastUpdate) > 3600 * 1000);

    if (cacheExpired) {
      const lastFail = await redis.get(REDIS_KEY_LAST_FAIL);
      const failedRecently = lastFail && (Date.now() - Number(lastFail) < FAIL_COOLDOWN_MS);
      if (failedRecently) {
        console.log("Skipping PhishTank refresh due to recent failure cooldown.");
        return;
      }

      console.log("PhishTank cache expired or missing. Refreshing Redis...");
      const normalizeCandidate = (url: string) => {
        // Only append format=json if it's not already present and the URL is not a gzipped dump.
        if (!url.includes("format=json") && !url.endsWith(".gz")) {
          const separator = url.includes("?") ? "&" : "?";
          return `${url}${separator}format=json`;
        }
        return url;
      };

      const candidates = [
        process.env.PHISHTANK_API_URL
          ? normalizeCandidate(process.env.PHISHTANK_API_URL)
          : undefined,
        ...DEFAULT_PHISHTANK_URLS,
      ].filter(Boolean) as string[];

      try {
        let succeeded = false;
        let totalUrlsProcessed = 0;

        for (const candidate of candidates) {
          console.log(`Fetching PhishTank from: ${candidate}`);
          try {
            const response = await axios.get(candidate, {
              timeout: 30000,
              headers: { "User-Agent": "phishtank/PhishermanScanner" },
              responseType: "arraybuffer",
              maxContentLength: MAX_FEED_BYTES,
              maxBodyLength: MAX_FEED_BYTES,
              decompress: true,
              validateStatus: () => true, // Accept all status codes, we'll check manually
            });

            const status = response?.status;
            if (typeof status !== "number") {
              throw new Error("PhishTank response missing status code");
            }

            // Check for error status codes
            if (status < 200 || status >= 300) {
              console.error(`PhishTank endpoint returned status ${status} for ${candidate}`);
              continue; // Try next candidate
            }

            console.log(`PhishTank API status: ${status}`);

            const headers = (response as any)?.headers || {};
            const contentType = headers["content-type"] || headers["Content-Type"];
            if (contentType && contentType.startsWith("image/")) {
              console.error(`PhishTank endpoint returned image content-type (${contentType}) for ${candidate}`);
              continue; // Try next candidate
            }

            const buffer = Buffer.from(response.data ?? []);

            if (buffer.length > MAX_FEED_BYTES) {
              console.error(
                `PhishTank feed too large (${buffer.length} bytes > ${MAX_FEED_BYTES}); aborting parse.`
              );
              continue; // Try next candidate
            }

            if (buffer.length === 0) {
              console.error(`PhishTank endpoint returned empty response for ${candidate}`);
              continue; // Try next candidate
            }

            // Decompress if needed
            let rawString: string;
            if (buffer[0] === 0x1f && buffer[1] === 0x8b) {
              rawString = pako.inflate(new Uint8Array(buffer), { to: "string" });
            } else {
              rawString = buffer.toString();
            }
            // Buffer will be GC'd when it goes out of scope

            // Parse JSON
            let data: any;
            try {
              data = JSON.parse(rawString);
              console.log(`PhishTank parsed successfully. Total entries: ${Array.isArray(data) ? data.length : 0}`);
            } catch (parseError) {
              console.error("Failed to parse PhishTank response as JSON.");
              console.error(`First 200 chars of response: ${rawString.substring(0, 200)}`);
              // Clear rawString before continuing
              rawString = "";
              continue;
            }

            // Clear rawString immediately after parsing to free memory
            rawString = "";

            if (!Array.isArray(data) || data.length === 0) {
              console.warn("PhishTank response contained no entries.");
              data = null;
              continue;
            }

            // Log sample entry
            if (data[0]) {
              console.log("PhishTank Sample Entry:", JSON.stringify(data[0], null, 2));
            }

            // Process entries in batches and write directly to Redis (memory-efficient)
            await redis.del(REDIS_KEY_URLS);

            const urlBatch: string[] = [];
            let processedCount = 0;

            for (const entry of data) {
              if (entry?.url) {
                urlBatch.push(entry.url);
                processedCount++;

                // Write to Redis in batches to avoid memory buildup
                if (urlBatch.length >= PROCESSING_BATCH_SIZE) {
                  await (redis as any).sadd(REDIS_KEY_URLS, ...urlBatch);
                  totalUrlsProcessed += urlBatch.length;
                  urlBatch.length = 0; // Clear array efficiently

                  // Force garbage collection hint by yielding
                  if (processedCount % (PROCESSING_BATCH_SIZE * 10) === 0) {
                    await new Promise(resolve => setImmediate(resolve));
                  }
                }
              }
            }

            // Write remaining URLs
            if (urlBatch.length > 0) {
              await (redis as any).sadd(REDIS_KEY_URLS, ...urlBatch);
              totalUrlsProcessed += urlBatch.length;
            }

            // Clear data immediately after processing
            data = null;

            if (totalUrlsProcessed > 0) {
              await redis.set(REDIS_KEY_LAST_UPDATE, Date.now().toString());
              console.log(`PhishTank Redis cache populated: ${totalUrlsProcessed} URLs.`);
              succeeded = true;
              break;
            } else {
              console.warn("PhishTank response contained no URL entries; leaving cache unchanged.");
            }
          } catch (candidateErr: any) {
            // Handle axios errors specifically
            if (candidateErr?.response) {
              const status = candidateErr.response.status;
              const contentType = candidateErr.response.headers?.["content-type"] || candidateErr.response.headers?.["Content-Type"];
              console.error(`PhishTank fetch failed for ${candidate}: HTTP ${status}${contentType ? ` (${contentType})` : ""}`);
            } else if (candidateErr?.code === "ERR_BAD_REQUEST" || candidateErr?.code === "ECONNREFUSED" || candidateErr?.code === "ETIMEDOUT") {
              console.error(`PhishTank fetch failed for ${candidate}: ${candidateErr.code}`);
            } else {
              console.error(`PhishTank fetch failed for ${candidate}:`, candidateErr?.message || candidateErr);
            }
            // Continue to next candidate
          }
        }

        if (!succeeded) {
          await redis.set(REDIS_KEY_LAST_FAIL, Date.now().toString());
          throw new Error("All PhishTank endpoints failed; backing off.");
        } else {
          await redis.del(REDIS_KEY_LAST_FAIL);
        }
      } catch (err) {
        console.error("PhishTank refresh error:", err);
      }
    }
  } catch (err) {
    console.error("PhishTank refresh error:", err);
  }
}

function normalize(u: string): string {
  try {
    return new URL(u).hostname.replace("www.", "").toLowerCase();
  } catch {
    return u.toLowerCase();
  }
}

import { Checker, CheckResult } from "../types";

export async function checkPhishTank(url: string): Promise<CheckResult> {
  try {
    // Exact URL Match
    const isUrlMember = await redis.sismember(REDIS_KEY_URLS, url);
    if (isUrlMember) {
      return {
        score: 100,
        reason: "Exact URL match in PhishTank database",
      };
    }

  } catch (err) {
    console.error("PhishTank check error:", err);
  }

  return { score: 0 };
}

export const PhishTankChecker: Checker = {
  name: "phishtank",
  check: checkPhishTank,
};


