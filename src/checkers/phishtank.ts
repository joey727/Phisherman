import axios from "axios";
import dotenv from "dotenv";
import { URL } from "node:url";
import redis from "../utils/redis";
import readline from "node:readline";
import zlib from "node:zlib";
import { Checker, CheckResult } from "../types";

dotenv.config();

// Prefer CSV.GZ because it can be processed in a streaming, constant-memory way.
// The JSON dump is typically a giant array and requires buffering/parsing, which is risky on small instances.
const FEED_CSV = "https://data.phishtank.com/data/online-valid.csv.gz";
const FEED_JSON = "https://data.phishtank.com/data/online-valid.json";
const REDIS_KEY_URLS = "phishtank_urls";
const REDIS_KEY_LAST_UPDATE = "phishtank_last_update";
const REDIS_KEY_LAST_FAIL = "phishtank_last_fail";
const FAIL_COOLDOWN_MS = 15 * 60 * 1000; // 15 mins
const SADD_BATCH_SIZE = 200; // Upstash request-size friendly (URLs can be long)

export async function loadPhishTank() {
  try {
    const lastUpdate = await redis.get(REDIS_KEY_LAST_UPDATE);
    // Refresh every hour
    const cacheExpired = !lastUpdate || (Date.now() - Number(lastUpdate) > 3600 * 1000);

    if (!cacheExpired) return;

    const lastFail = await redis.get(REDIS_KEY_LAST_FAIL);
    if (lastFail && (Date.now() - Number(lastFail) < FAIL_COOLDOWN_MS)) {
      console.log("Skipping PhishTank refresh due to cooldown.");
      return;
    }

    console.log("PhishTank cache expired. Starting resilient refresh...");

    // If user supplies a URL, we try it first; otherwise we default to the streaming CSV.GZ dump.
    const primaryUrl = process.env.PHISHTANK_API_URL || FEED_CSV;
    const secondaryUrl = primaryUrl.includes("csv") ? FEED_JSON : FEED_CSV;

    let success = await attemptFetchAndPopulate(primaryUrl);

    if (!success) {
      console.warn(`Primary PhishTank fetch/parse failed (${primaryUrl}). Attempting fallback to ${secondaryUrl}...`);
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
  try {
    console.log(`PhishTank: Attempting to fetch from ${url}...`);

    const response = await axios.get(url, {
      timeout: 120000, // Increased timeout for large files
      headers: {
        "User-Agent": "phishtank/PhishermanScanner",
        "Accept": "application/octet-stream, application/gzip, */*",
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
      return false;
    }

    const contentType = response.headers?.["content-type"];
    if (contentType && contentType.startsWith("image/")) {
      console.error(`PhishTank fetch returned unexpected content-type ${contentType} for ${url}`);
      return false;
    }

    let stream = response.data;
    // Check if response is gzipped by URL pattern OR content-type header
    const isGzipped = url.includes(".gz") ||
      contentType?.includes("gzip") ||
      contentType?.includes("application/x-gzip");

    console.log(`PhishTank: Content-Type=${contentType}, isGzipped=${isGzipped}`);

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

    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
    const isJson = url.includes(".json") || response.headers?.["content-type"]?.includes("json");

    await redis.del(tempUrlsKey);
    let totalProcessed = 0;

    if (isJson) {
      // JSON dumps are often huge arrays and require buffering. On small instances this can OOM.
      // We intentionally fail fast here so the caller can fall back to the streaming CSV dump.
      console.warn(`PhishTank endpoint looks like JSON (${url}); skipping to avoid large in-memory buffering.`);
      return false;
    }

    totalProcessed = await populateFromCsvStream(rl, tempUrlsKey);

    if (totalProcessed > 0) {
      await redis.rename(tempUrlsKey, REDIS_KEY_URLS);
      console.log(`PhishTank Redis cache populated with ${totalProcessed} entries (${url}).`);
      return true;
    }
  } catch (err: any) {
    console.error(`Fetch failed for ${url}:`, err.message);
  } finally {
    await redis.del(tempUrlsKey);
  }
  return false;
}

async function populateFromJson(data: any, key: string): Promise<number> {
  if (!Array.isArray(data)) return 0;
  const batchSize = SADD_BATCH_SIZE;
  let batch: string[] = [];
  let count = 0;

  for (const entry of data) {
    if (entry.url) {
      batch.push(normalize(entry.url));
      count++;
    }
    if (batch.length >= batchSize) {
      await (redis as any).sadd(key, ...batch);
      batch = [];
    }
  }
  if (batch.length > 0) await (redis as any).sadd(key, ...batch);
  return count;
}

async function populateFromCsvStream(rl: any, key: string): Promise<number> {
  const batchSize = SADD_BATCH_SIZE;
  let batch: string[] = [];
  let count = 0;

  for await (const line of rl) {
    const url = parseUrlFromCsvLine(line);
    if (url) {
      batch.push(normalize(url));
      count++;
    }
    if (batch.length >= batchSize) {
      await (redis as any).sadd(key, ...batch);
      batch = [];
      await new Promise(resolve => setImmediate(resolve));
    }
  }
  if (batch.length > 0) await (redis as any).sadd(key, ...batch);
  return count;
}

async function populateFromCsvString(data: string, key: string): Promise<number> {
  const lines = data.split(/\r?\n/);
  const batchSize = SADD_BATCH_SIZE;
  let batch: string[] = [];
  let count = 0;

  for (const line of lines) {
    const url = parseUrlFromCsvLine(line);
    if (url) {
      batch.push(normalize(url));
      count++;
    }
    if (batch.length >= batchSize) {
      await (redis as any).sadd(key, ...batch);
      batch = [];
    }
  }
  if (batch.length > 0) await (redis as any).sadd(key, ...batch);
  return count;
}

function parseUrlFromCsvLine(line: string): string | undefined {
  if (!line || line.startsWith("phish_id")) return undefined;
  const parts = line.split('","');
  if (parts.length >= 2) return parts[1].replace(/"/g, "");
  const simpleParts = line.split(',');
  if (simpleParts.length >= 2) return simpleParts[1].replace(/"/g, "");
  return undefined;
}

function normalize(u: string): string {
  try {
    // PhishTank URLs are often full paths. We store full URL for exact match.
    // If we wanted to store hostnames only, we would do:
    // return new URL(u).hostname.replace("www.", "").toLowerCase();
    // But checkPhishTank checks full URL existence first. 
    // Wait, previous implementation stored full URLs in REDIS_KEY_URLS. 
    // So we keep it as is, but maybe trim.
    return u.trim();
  } catch {
    return u.trim();
  }
}


export async function checkPhishTank(url: string): Promise<CheckResult> {
  try {
    // exact url match is tricky as phishtank urls can have query params
    // and we store the full url in the database
    // so we need to check for the url as is
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


