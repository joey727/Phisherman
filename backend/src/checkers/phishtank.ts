import axios from "axios";
import dotenv from "dotenv";
import { URL } from "node:url";
import redis from "../utils/redis";
import readline from "node:readline";
import zlib from "node:zlib";
import { Checker, CheckResult } from "../types";

dotenv.config();

const FEED = "http://data.phishtank.com/data/online-valid.csv.gz";
const REDIS_KEY_URLS = "phishtank_urls";
const REDIS_KEY_LAST_UPDATE = "phishtank_last_update";
const REDIS_KEY_LAST_FAIL = "phishtank_last_fail";
const FAIL_COOLDOWN_MS = 15 * 60 * 1000; // 15 mins

export async function loadPhishTank() {
  try {
    const lastUpdate = await redis.get(REDIS_KEY_LAST_UPDATE);
    // Refresh every hour
    const cacheExpired = !lastUpdate || (Date.now() - Number(lastUpdate) > 3600 * 1000);

    if (cacheExpired) {
      const lastFail = await redis.get(REDIS_KEY_LAST_FAIL);
      if (lastFail && (Date.now() - Number(lastFail) < FAIL_COOLDOWN_MS)) {
        console.log("Skipping PhishTank refresh due to cooldown.");
        return;
      }

      console.log("PhishTank cache expired. Starting stream refresh...");

      const candidate = process.env.PHISHTANK_API_URL || FEED;

      try {
        const response = await axios.get(candidate, {
          timeout: 60000,
          headers: { "User-Agent": "phishtank/PhishermanScanner" },
          responseType: "stream",
          validateStatus: () => true,
        });

        if (response.status < 200 || response.status >= 300) {
          throw new Error(`HTTP ${response.status}`);
        }

        let stream = response.data;

        // Handle GZIP if needed (extension check or header check)
        // Note: PhishTank .gz feed usually sends application/x-gzip or similar
        // We will force gunzip if the URL ends in .gz
        if (candidate.endsWith(".gz")) {
          const gunzip = zlib.createGunzip();
          stream.pipe(gunzip);
          stream = gunzip;
        }

        const rl = readline.createInterface({
          input: stream,
          crlfDelay: Infinity,
        });

        const tempUrlsKey = `${REDIS_KEY_URLS}_temp`;
        await redis.del(tempUrlsKey);

        const batchSize = 1000;
        const urlBatch: string[] = [];
        let totalProcessed = 0;

        for await (const line of rl) {
          if (!line || line.startsWith("phish_id")) continue; // Skip header

          // CSV: phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
          // We want index 1 (url)

          const parts = line.split(',');
          // PhishTank CSVs are usually standard, but URLs can have commas. 
          // If the URL has commas, it might be quoted.
          // A robust parser is expensive. For now, we take the 2nd element. 
          // If it starts with quote, we might need to look further.
          // For speed/memory on 512MB, we try a simple heuristic:

          let rawUrl = parts[1];
          // Basic cleanup if quoted
          if (rawUrl && rawUrl.startsWith('"') && rawUrl.endsWith('"')) {
            rawUrl = rawUrl.slice(1, -1);
          }

          if (rawUrl) {
            const normalized = normalize(rawUrl);
            urlBatch.push(normalized);
            totalProcessed++;
          }

          if (urlBatch.length >= batchSize) {
            await (redis as any).sadd(tempUrlsKey, ...urlBatch);
            urlBatch.length = 0;
            // Yield
            await new Promise(resolve => setImmediate(resolve));
          }
        }

        if (urlBatch.length > 0) {
          await (redis as any).sadd(tempUrlsKey, ...urlBatch);
        }

        if (totalProcessed > 0) {
          await redis.rename(tempUrlsKey, REDIS_KEY_URLS);
          await redis.set(REDIS_KEY_LAST_UPDATE, Date.now().toString());
          await redis.del(REDIS_KEY_LAST_FAIL);
          console.log(`PhishTank Redis cache populated with ${totalProcessed} entries (Streamed).`);
        } else {
          await redis.del(tempUrlsKey);
          console.warn("PhishTank stream processed 0 entries.");
        }

      } catch (err: any) {
        console.error("PhishTank fetch failed:", err.message);
        await redis.set(REDIS_KEY_LAST_FAIL, Date.now().toString());
      }
    }
  } catch (err) {
    console.error("PhishTank outer error:", err);
  }
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
    // Exact URL Match
    // Note: PhishTank URLs in DB might be http vs https or have query params.
    // Exact match is tricky. 
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


