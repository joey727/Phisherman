import axios from "axios";
import dotenv from "dotenv";
import { URL } from "node:url";
import redis from "../utils/redis";
import readline from "node:readline";
import zlib from "node:zlib";
import { BloomFilter } from "../utils/bloom";
import { Checker, CheckResult, ParsedUrl } from "../types";
import { getBloomStore } from "../utils/bloomStore";
import { incMetric } from "../utils/metrics";

dotenv.config();

// Prefer CSV.GZ because it can be processed in a streaming, constant-memory way.
// The JSON dump is typically a giant array and requires buffering/parsing, which is risky on small instances.
const FEED_CSV = "https://data.phishtank.com/data/online-valid.csv.gz";
const FEED_JSON = "https://data.phishtank.com/data/online-valid.json";
const REDIS_KEY_URLS = "phishtank_urls";
const REDIS_KEY_BLOOM = "phishtank_bloom";
const REDIS_KEY_LAST_UPDATE = "phishtank_last_update";
const REDIS_KEY_LAST_FAIL = "phishtank_last_fail";
const FAIL_COOLDOWN_MS = 15 * 60 * 1000; // 15 mins
const SADD_BATCH_SIZE = 200; // Upstash request-size friendly (URLs can be long)

export async function loadPhishTank() {
  try {
    const lastUpdate = await redis.get(REDIS_KEY_LAST_UPDATE);
    // Refresh every hour
    const cacheExpired =
      !lastUpdate || Date.now() - Number(lastUpdate) > 3600 * 1000;

    if (!cacheExpired) return;

    const lastFail = await redis.get(REDIS_KEY_LAST_FAIL);
    if (lastFail && Date.now() - Number(lastFail) < FAIL_COOLDOWN_MS) {
      console.log("Skipping PhishTank refresh due to cooldown.");
      return;
    }

    console.log("PhishTank cache expired. Starting resilient refresh...");

    // If user supplies a URL, we try it first; otherwise we default to the streaming CSV.GZ dump.
    const primaryUrl = process.env.PHISHTANK_API_URL || FEED_CSV;
    const secondaryUrl = primaryUrl.includes("csv") ? FEED_JSON : FEED_CSV;

    let success = await attemptFetchAndPopulate(primaryUrl);

    if (!success) {
      console.warn(
        `Primary PhishTank fetch/parse failed (${primaryUrl}). Attempting fallback to ${secondaryUrl}...`,
      );
      success = await attemptFetchAndPopulate(secondaryUrl);
    }

    if (success) {
      await redis.set(REDIS_KEY_LAST_UPDATE, Date.now().toString());
      await redis.del(REDIS_KEY_LAST_FAIL);
    } else {
      await redis.set(REDIS_KEY_LAST_FAIL, Date.now().toString());
    }
  } catch (err) {
    console.error("PhishTank outer error:", err);
  }
}

async function attemptFetchAndPopulate(url: string): Promise<boolean> {
  const tempUrlsKey = `${REDIS_KEY_URLS}_temp`;
  let stream: any = null;
  let rl: any = null;
  try {
    console.log(`PhishTank: Attempting to fetch from ${url}...`);

    const response = await axios.get(url, {
      timeout: 120000, // Increased timeout for large files
      headers: {
        "User-Agent": "phishtank/PhishermanScanner",
        Accept: "application/octet-stream, application/gzip, */*",
      },
      responseType: "stream",
      maxRedirects: 10, // PhishTank redirects to CDN
      decompress: false, // We handle gzip decompression manually
      // Don't throw on non-200; we'll inspect and fall back.
      validateStatus: () => true,
    });

    const status = response.status;
    const finalUrl = response.request?.res?.responseUrl || url;
    console.log(`PhishTank: Response status ${status} from ${finalUrl}`);

    if (status !== 200) {
      console.error(`PhishTank fetch returned status ${status} for ${url}`);
      response.data?.destroy?.();
      return false;
    }

    const contentType = response.headers?.["content-type"];
    if (contentType && contentType.startsWith("image/")) {
      console.error(
        `PhishTank fetch returned unexpected content-type ${contentType} for ${url}`,
      );
      response.data?.destroy?.();
      return false;
    }

    stream = response.data;
    // Check if response is gzipped by URL pattern OR content-type header
    const isGzipped =
      url.includes(".gz") ||
      contentType?.includes("gzip") ||
      contentType?.includes("application/x-gzip");

    console.log(
      `PhishTank: Content-Type=${contentType}, isGzipped=${isGzipped}`,
    );

    if (isGzipped) {
      const gunzip = zlib.createGunzip();
      // Pipe the response stream through gunzip decompressor
      response.data.pipe(gunzip);
      stream = gunzip;

      // Handle decompression errors
      gunzip.on("error", (err) => {
        console.error("Gunzip decompression error:", err.message);
      });
    }

    rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
    const isJson =
      url.includes(".json") ||
      response.headers?.["content-type"]?.includes("json");

    await redis.del(tempUrlsKey);
    let totalProcessed = 0;

    if (isJson) {
      // JSON dumps are often huge arrays and require buffering. On small instances this can OOM.
      // We intentionally fail fast here so the caller can fall back to the streaming CSV dump.
      console.warn(
        `PhishTank endpoint looks like JSON (${url}); skipping to avoid large in-memory buffering.`,
      );
      rl.close();
      stream.destroy?.();
      response.data?.destroy?.();
      return false;
    }

    totalProcessed = await populateFromCsvStream(rl, tempUrlsKey);

    if (totalProcessed > 0) {
      await redis.rename(tempUrlsKey, REDIS_KEY_URLS);
      console.log(
        `PhishTank Redis cache populated with ${totalProcessed} entries (${url}).`,
      );
      return true;
    }
  } catch (err: any) {
    console.error(`Fetch failed for ${url}:`, err.message);
  } finally {
    // Ensure stream resources are cleaned up
    rl?.close?.();
    stream?.destroy?.();
    await redis.del(tempUrlsKey);
  }
  return false;
}
async function populateFromCsvStream(rl: any, key: string): Promise<number> {
  const batchSize = SADD_BATCH_SIZE;
  let batch: string[] = [];
  let count = 0;

  // Build a Bloom filter in-memory as we stream so we can persist a compact
  // probabilistic representation for fast membership checks.
  const bloom = new BloomFilter();

  for await (const line of rl) {
    const url = parseUrlFromCsvLine(line);
    if (url) {
      const n = normalize(url);
      batch.push(n);
      bloom.add(n);
      count++;
    }
    if (batch.length >= batchSize) {
      await (redis as any).sadd(key, ...batch);
      batch = [];
      await new Promise((resolve) => setImmediate(resolve));
    }
  }
  if (batch.length > 0) await (redis as any).sadd(key, ...batch);
  try {
    // Persist compact bloom to redis for faster membership checks later.
    await redis.set(REDIS_KEY_BLOOM, bloom.serialize());
  } catch (err) {
    console.error("PhishTank: Failed to persist bloom filter:", err);
  }
  return count;
}

function parseUrlFromCsvLine(line: string): string | undefined {
  if (!line || line.startsWith("phish_id")) return undefined;
  const parts = line.split('","');
  if (parts.length >= 2) return parts[1].replace(/"/g, "");
  const simpleParts = line.split(",");
  if (simpleParts.length >= 2) return simpleParts[1].replace(/"/g, "");
  return undefined;
}

function normalize(u: string): string {
  try {
    return u.trim();
  } catch {
    return u.trim();
  }
}

export async function checkPhishTank(
  url: string,
  _parsed?: ParsedUrl,
): Promise<CheckResult> {
  try {
    // First try a compact Bloom filter (fast, in-memory-ish). If it's a false
    // positive we will still verify against the authoritative Redis set.
    try {
      // Use BloomStore abstraction which prefers RedisBloom when enabled.
      try {
        const store = await getBloomStore(REDIS_KEY_BLOOM);
        const exists = await store.has(url);
        if (exists) {
          const isUrlMember = await redis.sismember(REDIS_KEY_URLS, url);
          if (isUrlMember) {
            return {
              score: 100,
              reason: "Exact URL match in PhishTank database (via bloom+set)",
            };
          }
        }
      } catch (bErr) {
        console.warn("PhishTank: BloomStore check failed:", String(bErr));
      }
    } catch (err) {
      console.warn("PhishTank: bloom path error:", String(err));
    }

    // As a final check, try exact Redis set membership.
    const isUrlMember = await redis.sismember(REDIS_KEY_URLS, url);
    if (isUrlMember) {
      return {
        score: 100,
        reason: "Exact URL match in PhishTank database",
      };
    }

    // Not found locally; enqueue for deep analysis and optionally check remote PhishTank API.
    try {
      await (redis as any).rpush("analysis_queue", url);
      try {
        await incMetric("enqueued_for_analysis", 1);
      } catch {}
    } catch (e) {
      console.warn("PhishTank: enqueue failed:", String(e));
    }

    // Optionally, use PhishTank's remote API as a last resort. This is slower and less reliable than the local cache, but can catch very recent additions that haven't been ingested yet.
    const apiKey = process.env.PHISHTANK_API_KEY;
    if (apiKey) {
      try {
        const res = await axios.get(
          `https://checkurl.phishtank.com/checkurl/?format=json&app_key=${apiKey}&url=${encodeURIComponent(url)}`,
          { timeout: 5000 },
        );
        const matched =
          res.data?.results?.valid === "true" || res.data?.valid === true;
        if (matched) {
          return { score: 100, reason: "PhishTank remote API confirmed URL" };
        }
      } catch (err) {
        console.warn("PhishTank remote API error:", String(err));
      }
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
