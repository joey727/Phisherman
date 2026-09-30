import redis from "../utils/redis";
import { getBloomStore } from "../utils/bloomStore";
import { incMetric } from "../utils/metrics";

export async function ingestUrls(
  redisKey: string,
  urls: string[],
  options?: { batchSize?: number },
) {
  const batchSize = options?.batchSize || 500;
  const bloomKey = `${redisKey}_bloom`;
  const bloomStore = await getBloomStore(bloomKey);

  // Add in small batches to avoid large redis commands
  for (let i = 0; i < urls.length; i += batchSize) {
    const batch = urls.slice(i, i + batchSize);
    try {
      await (redis as any).sadd(redisKey, ...batch);
      await incMetric("feed_urls_added", batch.length);
    } catch (err) {
      console.warn("ingest: redis.sadd failed:", String(err));
    }
    await bloomStore.addBatch(batch);
  }

  try {
    // Persist local bloom if needed (noop when using RedisBloom)
    await bloomStore.persist();
  } catch (err) {
    console.warn("ingest: failed to persist bloom:", String(err));
  }
}
