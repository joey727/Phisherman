import axios from "axios";
import redis from "../utils/redis";

const FEED = "https://urlhaus.abuse.ch/downloads/json_recent/";
const REDIS_KEY_BLACKLIST = "urlhaus_blacklist";
const REDIS_KEY_LAST_UPDATE = "urlhaus_last_update";

export async function loadURLHaus() {
  try {
    const lastUpdate = await redis.get(REDIS_KEY_LAST_UPDATE);
    const cacheExpired = !lastUpdate || (Date.now() - Number(lastUpdate) > 3600 * 1000);

    if (cacheExpired) {
      console.log("URLHaus cache expired or missing. Refreshing Redis...");
      const response = await axios.get(FEED, {
        timeout: 30000,
        responseType: "stream",
        headers: { "User-Agent": "PhishermanScanner/1.0" },
      });

      let data = "";
      for await (const chunk of response.data) {
        data += chunk.toString();
      }

      const json = JSON.parse(data);
      const urls: string[] = (json.urls || []).map((entry: any) => entry.url);

      if (urls.length > 0) {
        // Clear existing set and repopulate
        await redis.del(REDIS_KEY_BLACKLIST);

        // Redis handle large sets well, but we should batch SADD calls
        const batchSize = 1000;
        for (let i = 0; i < urls.length; i += batchSize) {
          const batch = urls.slice(i, i + batchSize);
          await (redis.sadd as any)(REDIS_KEY_BLACKLIST, ...batch);
        }
        await redis.set(REDIS_KEY_LAST_UPDATE, Date.now().toString());
        console.log(`URLHaus Redis cache populated with ${urls.length} entries.`);
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

    const isMember = await redis.sismember(REDIS_KEY_BLACKLIST, url);

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
