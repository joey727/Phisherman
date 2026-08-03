import redis from "../utils/redis";
import { BloomFilter } from "../utils/bloom";
import { getBloomStore } from "../utils/bloomStore";
import { incMetric } from "../utils/metrics";

const DEFAULT_BLOOM_M = 8_000_000;
const DEFAULT_BLOOM_K = 7;

export async function ingestUrls(
  redisKey: string,
  urls: string[],
  options?: { batchSize?: number },
) {
  const batchSize = options?.batchSize || 500;
  const bloomKey = `${redisKey}_bloom`;
  const bloomTemp = `${bloomKey}_tmp`;
  const metaKey = `${bloomKey}_meta`;

  // Bloom store abstraction (uses RedisBloom when enabled, otherwise local serialized bloom)
  const bloomStore = await getBloomStore(bloomKey);
  let bloom: BloomFilter | null = null;
  try {
    // if the BloomStore exposed a local filter, use it for local operations
    // (getBloomStore already initialized the local bloom when needed)
    // @ts-ignore
    bloom = (bloomStore as any).local || null;
  } catch {
    bloom = new BloomFilter(DEFAULT_BLOOM_M, DEFAULT_BLOOM_K);
  }

  // Add in small batches to avoid large redis commands
  for (let i = 0; i < urls.length; i += batchSize) {
    const batch = urls.slice(i, i + batchSize);
    try {
      await (redis as any).sadd(redisKey, ...batch);
      await incMetric("feed_urls_added", batch.length);
    } catch (err) {
      console.warn("ingest: redis.sadd failed:", String(err));
    }
    for (const u of batch) await bloomStore.addBatch([u]);
  }

  try {
    // Persist local bloom if needed (noop when using RedisBloom)
    await bloomStore.persist();
  } catch (err) {
    console.warn("ingest: failed to persist bloom:", String(err));
  }
}
