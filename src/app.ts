import express, { Request, Response } from "express";
import cors from "cors";
import { analyzeUrl } from "./Scanner";
import { apiLimiter } from "./middleware/ratelimit";
import { backpressure, getInFlightCount } from "./middleware/backpressure";
import { getMetric } from "./utils/metrics";
import redis from "./utils/redis";

export function createApp() {
  const app = express();

  app.set("trust proxy", 1);
  app.use(express.json());
  app.use(cors());
  app.use(backpressure);

  app.get("/health", (_req: Request, res: Response) => {
    return res.json({ status: "ok" });
  });

  app.get("/metrics", async (_req: Request, res: Response) => {
    try {
      const feedUrls = await getMetric("feed_urls_added");
      const processed = await getMetric("worker_processed");
      const enqueued = await getMetric("enqueued_for_analysis");
      const queueLen =
        Number(await (redis as any).llen("analysis_queue")).valueOf() || 0;
      const inFlight = getInFlightCount();

      return res.json({ feedUrls, processed, enqueued, queueLen, inFlight });
    } catch (err) {
      return res
        .status(500)
        .json({ error: "metrics error", detail: String(err) });
    }
  });

  app.post("/api/check", apiLimiter, async (req: Request, res: Response) => {
    const { url } = req.body;
    if (!url || typeof url !== "string") {
      return res.status(400).json({ error: "Missing 'url' in body" });
    }

    try {
      const result = await analyzeUrl(url);
      return res.json(result);
    } catch (err) {
      console.error("analyze error:", err);
      return res.status(500).json({
        error: "Server error",
        detail: String(err),
      });
    }
  });

  return app;
}
