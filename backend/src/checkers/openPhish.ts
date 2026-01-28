import axios from "axios";
import { URL } from "node:url";
import redis from "../utils/redis";
import { Checker, CheckResult } from "../types";

const FEED = "https://openphish.com/feed.txt";
const REDIS_KEY_URLS = "openphish_urls";
const REDIS_KEY_HOSTS = "openphish_hosts";
const REDIS_KEY_LAST_UPDATE = "openphish_last_update";

export async function loadOpenPhish() {
  try {
    const lastUpdate = await redis.get(REDIS_KEY_LAST_UPDATE);
    const cacheExpired = !lastUpdate || (Date.now() - Number(lastUpdate) > 15 * 60 * 1000);

    if (cacheExpired) {
      console.log("OpenPhish cache expired or missing. Refreshing Redis...");
      const response = await axios.get(FEED, { timeout: 15000 });
      const lines = response.data.split("\n");

      if (lines.length > 0) {
        const tempUrlsKey = `${REDIS_KEY_URLS}_temp`;
        const tempHostsKey = `${REDIS_KEY_HOSTS}_temp`;

        await redis.del(tempUrlsKey);
        await redis.del(tempHostsKey);

        const urlBatch: string[] = [];
        const hostBatch: string[] = [];

        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.length > 0) {
            urlBatch.push(trimmed);
            try {
              const u = new URL(trimmed);
              hostBatch.push(u.hostname);
            } catch {
              // ignore invalid URLs in feed
            }

            if (urlBatch.length >= 1000) {
              await (redis.sadd as any)(tempUrlsKey, ...urlBatch);
              urlBatch.length = 0;
            }
            if (hostBatch.length >= 1000) {
              await (redis.sadd as any)(tempHostsKey, ...hostBatch);
              hostBatch.length = 0;
            }
          }
        }

        if (urlBatch.length > 0) await (redis.sadd as any)(tempUrlsKey, ...urlBatch);
        if (hostBatch.length > 0) await (redis.sadd as any)(tempHostsKey, ...hostBatch);

        // Atomic swap
        await (redis as any).rename(tempUrlsKey, REDIS_KEY_URLS);
        await (redis as any).rename(tempHostsKey, REDIS_KEY_HOSTS);

        await redis.set(REDIS_KEY_LAST_UPDATE, Date.now().toString());
        console.log(`OpenPhish Redis cache updated. Entries: ${lines.length}`);
      }
    }
  } catch (err) {
    console.error("OpenPhish refresh error:", err);
  }
}

export async function checkOpenPhish(url: string): Promise<CheckResult> {
  try {
    // Check exact URL
    const urlMatch = await redis.sismember(REDIS_KEY_URLS, url);
    if (urlMatch) return { score: 100, reason: "Listed in OpenPhish URL database" };

    // Check Hostname
    try {
      const u = new URL(url.startsWith("http") ? url : `http://${url}`);
      const hostMatch = await redis.sismember(REDIS_KEY_HOSTS, u.hostname);
      if (hostMatch) return { score: 80, reason: "Domain listed in OpenPhish intelligence" };
    } catch {
      // ignore parse errors
    }
  } catch (err) {
    console.error("OpenPhish check error:", err);
  }
  return { score: 0 };
}

export const OpenPhishChecker: Checker = {
  name: "openphish",
  check: checkOpenPhish,
};


