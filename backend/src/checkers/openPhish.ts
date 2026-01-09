import axios from "axios";
import redis from "../utils/redis";

const FEED = "https://openphish.com/feed.txt";
const REDIS_KEY_BLACKLIST = "openphish_blacklist";
const REDIS_KEY_LAST_UPDATE = "openphish_last_update";

export async function loadOpenPhish() {
  try {
    const lastUpdate = await redis.get(REDIS_KEY_LAST_UPDATE);
    const cacheExpired = !lastUpdate || (Date.now() - Number(lastUpdate) > 15 * 60 * 1000); // 15 mins

    if (cacheExpired) {
      console.log("OpenPhish cache expired or missing. Refreshing Redis...");
      const response = await axios.get(FEED, {
        timeout: 10000,
      });

      const urls: string[] = response.data
        .split("\n")
        .map((x: string) => x.trim())
        .filter((x: string) => x.length > 0);

      if (urls.length > 0) {
        await redis.del(REDIS_KEY_BLACKLIST);

        const batchSize = 1000;
        for (let i = 0; i < urls.length; i += batchSize) {
          const batch = urls.slice(i, i + batchSize);
          await (redis.sadd as any)(REDIS_KEY_BLACKLIST, ...batch);
        }

        await redis.set(REDIS_KEY_LAST_UPDATE, Date.now().toString());
        console.log(`OpenPhish Redis cache populated with ${urls.length} entries.`);
      }
    }
  } catch (err) {
    console.error("OpenPhish refresh error:", err);
  }
}

export async function checkOpenPhish(url: string) {
  try {
    const setExists = await redis.exists(REDIS_KEY_BLACKLIST);
    if (!setExists) {
      await loadOpenPhish();
    } else {
      loadOpenPhish().catch(e => console.error("Background OpenPhish refresh failed:", e));
    }

    const isMember = await redis.sismember(REDIS_KEY_BLACKLIST, url);

    if (isMember) {
      return { score: 100, reason: "Listed in OpenPhish database" };
    }
  } catch (err) {
    console.error("OpenPhish check error:", err);
  }

  return { score: 0 };
}
