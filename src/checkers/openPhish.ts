import axios from "axios";
import { URL } from "node:url";
import readline from "node:readline";
import redis from "../utils/redis";
import { Checker, CheckResult, ParsedUrl } from "../types";
import { isTrustedApex } from "../utils/trustedApex";

const FEED = "https://openphish.com/feed.txt";
const REDIS_KEY_URLS = "openphish_urls";
const REDIS_KEY_HOSTS = "openphish_hosts";
const REDIS_KEY_LAST_UPDATE = "openphish_last_update";

export async function loadOpenPhish() {
  const tempUrlsKey = `${REDIS_KEY_URLS}_temp`;
  const tempHostsKey = `${REDIS_KEY_HOSTS}_temp`;
  let stream: any = null;
  let rl: any = null;
  try {
    const lastUpdate = await redis.get(REDIS_KEY_LAST_UPDATE);
    const cacheExpired = !lastUpdate || (Date.now() - Number(lastUpdate) > 15 * 60 * 1000);

    if (cacheExpired) {
      console.log("OpenPhish cache expired or missing. Refreshing Redis...");
      const response = await axios.get(FEED, {
        timeout: 15000,
        responseType: "stream",
      });

      stream = response.data;
      rl = readline.createInterface({
        input: stream,
        crlfDelay: Infinity,
      });

      await redis.del(tempUrlsKey);
      await redis.del(tempHostsKey);

      const urlBatch: string[] = [];
      const hostBatch: string[] = [];
      let lineCount = 0;

      for await (const line of rl) {
        const trimmed = line.trim();
        if (trimmed.length > 0) {
          lineCount++;
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
            await new Promise(resolve => setImmediate(resolve));
          }
          if (hostBatch.length >= 1000) {
            await (redis.sadd as any)(tempHostsKey, ...hostBatch);
            hostBatch.length = 0;
            await new Promise(resolve => setImmediate(resolve));
          }
        }
      }

      if (urlBatch.length > 0) await (redis.sadd as any)(tempUrlsKey, ...urlBatch);
      if (hostBatch.length > 0) await (redis.sadd as any)(tempHostsKey, ...hostBatch);

      if (lineCount > 0) {
        // Atomic swap
        await (redis as any).rename(tempUrlsKey, REDIS_KEY_URLS);
        await (redis as any).rename(tempHostsKey, REDIS_KEY_HOSTS);

        await redis.set(REDIS_KEY_LAST_UPDATE, Date.now().toString());
        console.log(`OpenPhish Redis cache updated. Entries: ${lineCount}`);
      } else {
        await redis.del(tempUrlsKey);
        await redis.del(tempHostsKey);
        console.warn("OpenPhish feed returned 0 entries.");
      }
    }
  } catch (err) {
    console.error("OpenPhish refresh error:", err);
  } finally {
    rl?.close?.();
    stream?.destroy?.();
    await redis.del(tempUrlsKey);
    await redis.del(tempHostsKey);
  }
}

export async function checkOpenPhish(url: string, parsed?: ParsedUrl): Promise<CheckResult> {
  try {
    // Check exact URL
    const urlMatch = await redis.sismember(REDIS_KEY_URLS, url);
    if (urlMatch) return { score: 100, reason: "Listed in OpenPhish URL database" };

    // Check Hostname -- use pre-parsed if available
    const hostname = parsed?.hostname;
    const hostNames = hostname
      ? [hostname]
      : (() => {
          try {
            const u = new URL(url.startsWith("http") ? url : `http://${url}`);
            return [u.hostname];
          } catch {
            return [];
          }
        })();

    for (const h of hostNames) {
      // Skip host-level match on trusted official apexes (exact URL match above
      // still catches real phishing on those apexes).
      if (isTrustedApex(h)) continue;
      const hostMatch = await redis.sismember(REDIS_KEY_HOSTS, h);
      if (hostMatch) return { score: 80, reason: "Domain listed in OpenPhish intelligence" };
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
