import axios from "axios";
import { URL } from "node:url";
import redis from "../utils/redis";

const FEED = "https://urlhaus.abuse.ch/downloads/json_recent/";
const REDIS_KEY_BLACKLIST = "urlhaus_blacklist";
const REDIS_KEY_LAST_UPDATE = "urlhaus_last_update";

export async function loadURLHaus() {
  try {
    const lastUpdate = await redis.get(REDIS_KEY_LAST_UPDATE);
    const cacheExpired = !lastUpdate || (Date.now() - Number(lastUpdate) > 3600 * 1000);

    if (cacheExpired) {
      const response = await axios.get(FEED, {
        timeout: 30000,
        headers: { "User-Agent": "PhishermanScanner/1.0" },
      });

      const json = response.data;
      let totalProcessed = 0;

      // Use a temporary key to ensure atomicity
      const tempKey = `${REDIS_KEY_BLACKLIST}_temp`;
      // Delete any stale temp key just in case
      await redis.del(tempKey);

      // Process entries in batches to avoid large intermediate arrays
      const batchSize = 1000;
      const urlBatch: string[] = [];

      for (const entries of Object.values(json)) {
        const entryArray = Array.isArray(entries) ? entries : [entries];

        for (const entry of entryArray) {
          if (entry?.url) {
            const normalized = normalize(entry.url);
            if (normalized) {
              urlBatch.push(normalized);

              if (urlBatch.length >= batchSize) {
                await (redis as any).sadd(tempKey, ...urlBatch);
                totalProcessed += urlBatch.length;
                urlBatch.length = 0; // Clear array efficiently
              }
            }
          }
        }
      }

      // Write remaining URLs
      if (urlBatch.length > 0) {
        await (redis as any).sadd(tempKey, ...urlBatch);
        totalProcessed += urlBatch.length;
      }

      if (totalProcessed > 0) {
        // Atomic swap
        await redis.rename(tempKey, REDIS_KEY_BLACKLIST);
        await redis.set(REDIS_KEY_LAST_UPDATE, Date.now().toString());
        console.log(`URLHaus Redis cache populated with ${totalProcessed} entries.`);
      } else {
        // Cleanup empty temp key if nothing processed
        await redis.del(tempKey);
      }
    }
  } catch (err) {
    console.error("URLHaus refresh error:", err);
  }
}

export async function checkURLHaus(url: string) {
  try {
    // Ensure background refresh is handled (don't await on every check for speed, 
    // unless the set is totally empty)
    const setExists = await redis.exists(REDIS_KEY_BLACKLIST);
    if (!setExists) {
      await loadURLHaus();
    } else {
      // Trigger background refresh if needed without blocking
      loadURLHaus().catch(e => console.error("Background URLHaus refresh failed:", e));
    }

    // Normalize URL before checking
    const normalizedUrl = normalize(url);
    const isMember = await redis.sismember(REDIS_KEY_BLACKLIST, normalizedUrl);

    if (isMember) {
      return {
        score: 100,
        reason: "URL matches URLHaus recent feed (malware/phishing)",
      };
    }
  } catch (err) {
    console.error("URLHaus check error:", err);
  }

  return { score: 0 };
}

function normalize(urlStr: string): string {
  try {
    const u = new URL(urlStr);
    // Normalize hostname and remove trailing slash from path
    let normalized = u.href;
    if (u.pathname.endsWith("/") && u.pathname.length > 1) {
      normalized = normalized.slice(0, -1);
    }
    return normalized;
  } catch {
    return urlStr;
  }
}
