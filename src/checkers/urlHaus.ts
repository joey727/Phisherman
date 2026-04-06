import axios from "axios";
import { URL } from "node:url";
import redis from "../utils/redis";
import readline from "node:readline";
import { Checker, CheckResult, ParsedUrl } from "../types";

const FEED = "https://urlhaus.abuse.ch/downloads/csv_online/"; // use direct CSV export link
const REDIS_KEY_BLACKLIST = "urlhaus_blacklist";
const REDIS_KEY_LAST_UPDATE = "urlhaus_last_update";

export async function loadURLHaus() {
  const tempKey = `${REDIS_KEY_BLACKLIST}_temp`;
  let stream: any = null;
  let rl: any = null;
  try {
    const lastUpdate = await redis.get(REDIS_KEY_LAST_UPDATE);
    // Refresh every 5 minutes (feed update rate) to stay current
    const cacheExpired =
      !lastUpdate || Date.now() - Number(lastUpdate) > 5 * 60 * 1000;

    if (cacheExpired) {
      console.log("URLHaus cache expired. Starting stream refresh...");

      const response = await axios.get(FEED, {
        timeout: 60000,
        headers: { "User-Agent": "Mozilla/5.0" },
      });

      if (response.status !== 200) {
        console.error(`URLHaus fetch returned status ${response.status}`);
        return;
      }

      const data = response.data;
      console.log(`URLHaus: Data received, length: ${data.length}`);
      console.log(`URLHaus: First 100 chars: ${data.substring(0, 100)}`);

      const lines = data.split("\n");
      console.log(`URLHaus: Total lines: ${lines.length}`);

      // Use a temporary key to ensure atomicity
      await redis.del(tempKey);

      const batchSize = 1000;
      const urlBatch: string[] = [];
      let totalProcessed = 0;

      for (const line of lines) {
        if (totalProcessed === 0)
          console.log(`URLHaus: First line received: ${line.substring(0, 50)}`);
        // Skip comments and empty lines
        if (!line || line.startsWith("#")) continue;

        const parts = line.split('","'); // Handle quoted CSV
        let rawUrl: string | undefined;

        if (parts.length >= 3) {
          rawUrl = parts[2].replace(/"/g, "");
        } else {
          const simpleParts = line.split(",");
          if (simpleParts.length >= 3) {
            rawUrl = simpleParts[2].replace(/"/g, "");
          }
        }

        if (rawUrl) {
          const normalized = normalize(rawUrl);
          if (normalized) {
            urlBatch.push(normalized);
            totalProcessed++;
          }
        }

        if (urlBatch.length >= batchSize) {
          await (redis as any).sadd(tempKey, ...urlBatch);
          // Update feed-specific bloom and metrics incrementally
          try {
            const { ingestUrls } = await import("../feeds/ingest");
            await ingestUrls(REDIS_KEY_BLACKLIST, urlBatch, { batchSize: 500 });
          } catch (err) {
            console.warn("URLHaus: ingest helper failed:", String(err));
          }
          urlBatch.length = 0;

          // Yield to event loop to keep server responsive
          await new Promise((resolve) => setImmediate(resolve));
        }
      }

      // Write remaining URLs
      if (urlBatch.length > 0) {
        await (redis as any).sadd(tempKey, ...urlBatch);
        try {
          const { ingestUrls } = await import("../feeds/ingest");
          await ingestUrls(REDIS_KEY_BLACKLIST, urlBatch, { batchSize: 500 });
        } catch (err) {
          console.warn(
            "URLHaus: ingest helper failed on final batch:",
            String(err),
          );
        }
      }

      if (totalProcessed > 0) {
        // Atomic swap
        await redis.rename(tempKey, REDIS_KEY_BLACKLIST);
        await redis.set(REDIS_KEY_LAST_UPDATE, Date.now().toString());
        console.log(
          `URLHaus Redis cache populated with ${totalProcessed} entries (Streamed).`,
        );
      } else {
        await redis.del(tempKey);
        console.warn("URLHaus stream processed 0 entries.");
      }
    }
  } catch (err) {
    console.error("URLHaus refresh error:", err);
  } finally {
    rl?.close?.();
    stream?.destroy?.();
    await redis.del(tempKey);
  }
}

export async function checkURLHaus(
  url: string,
  _parsed?: ParsedUrl,
): Promise<CheckResult> {
  try {
    const normalizedUrl = normalize(url);
    const isMember = await redis.sismember(REDIS_KEY_BLACKLIST, normalizedUrl);

    if (isMember) {
      return {
        score: 100,
        reason: "URL listed in URLHaus (Active Malware)",
      };
    }
  } catch (err) {
    console.error("URLHaus check error:", err);
  }

  return { score: 0 };
}

export const URLHausChecker: Checker = {
  name: "urlhaus",
  check: checkURLHaus,
};

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
