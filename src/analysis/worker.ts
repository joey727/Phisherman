import redis from "../utils/redis";
import { analyzeUrl } from "../Scanner";
import { enrichUrl } from "../utils/enrich";
import { incMetric } from "../utils/metrics";

const QUEUE_KEY = "analysis_queue";

export async function runWorkerLoop(stopSignal: () => boolean = () => false) {
  while (!stopSignal()) {
    try {
      // BRPOP with timeout 5 seconds for a simple loop-friendly worker
      const item = await (redis as any).brpop(QUEUE_KEY, 5).catch(() => null);
      if (!item) continue;
      // brpop returns [key, value]
      const payload = Array.isArray(item) ? item[1] : item;
      const url =
        typeof payload === "string"
          ? payload
          : JSON.parse(payload as string).url;
      if (!url) continue;

      // perform enrichment
      const meta = await enrichUrl(url).catch((e) => ({ error: String(e) }));

      // run full analysis (this will also cache results)
      const result = await analyzeUrl(url).catch((e) => ({ error: String(e) }));

      // Optionally store enrichment metadata
      try {
        await redis.hset("analysis_meta", {
          [url]: JSON.stringify({ meta, result, ts: Date.now() }),
        });
        await incMetric("worker_processed", 1);
      } catch (err) {
        console.warn("Worker: failed to persist meta", String(err));
      }
    } catch (err) {
      console.error("Worker loop error:", String(err));
      // small sleep to avoid busy loop on persistent errors
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
}
