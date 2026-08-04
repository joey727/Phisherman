import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import { analyzeUrl } from "./Scanner";
import { apiLimiter } from "./middleware/ratelimit";
import { authMiddleware } from "./middleware/auth";
import { backpressure, getInFlightCount } from "./middleware/backpressure";
import { getMetric } from "./utils/metrics";
import redis from "./utils/redis";
import {
  createApiKey,
  getApiKey,
  listApiKeys,
  updateApiKey,
  deleteApiKey,
} from "./utils/apiKeys";
import { ApiKeyTier } from "./types";

function requireAdmin(req: Request, res: Response, next: NextFunction) {
  if (!req.isAdmin) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

export function createApp() {
  const app = express();

  app.set("trust proxy", 1);
  app.use(express.json());
  app.use(cors());
  app.use(backpressure);
  app.use(authMiddleware);

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
      const tier = req.apiKey?.tier ?? "free";
      const result = await analyzeUrl(url, { tier });
      return res.json(result);
    } catch (err) {
      console.error("analyze error:", err);
      return res.status(500).json({
        error: "Server error",
        detail: String(err),
      });
    }
  });

  // Admin API key management
  app.post("/admin/keys", requireAdmin, async (req: Request, res: Response) => {
    const { name, tier } = req.body;

    if (!name || typeof name !== "string") {
      return res.status(400).json({ error: "Missing or invalid 'name'" });
    }

    const validTier: ApiKeyTier =
      ["free", "pro", "enterprise"].includes(tier) ? tier : "free";

    try {
      const result = await createApiKey(name, validTier);
      return res.status(201).json(result);
    } catch (err) {
      return res.status(500).json({ error: "Failed to create API key", detail: String(err) });
    }
  });

  app.get("/admin/keys", requireAdmin, async (_req: Request, res: Response) => {
    try {
      const keys = await listApiKeys();
      const safeKeys = keys.map((k) => ({
        hash: k.hash,
        prefix: k.prefix,
        name: k.name,
        tier: k.tier,
        enabled: k.enabled,
        createdAt: k.createdAt,
        lastUsedAt: k.lastUsedAt,
      }));
      return res.json({ keys: safeKeys });
    } catch (err) {
      return res.status(500).json({ error: "Failed to list API keys", detail: String(err) });
    }
  });

  app.get("/admin/keys/:hash", requireAdmin, async (req: Request, res: Response) => {
    try {
      const metadata = await getApiKey(req.params.hash);
      if (!metadata) {
        return res.status(404).json({ error: "API key not found" });
      }
      return res.json(metadata);
    } catch (err) {
      return res.status(500).json({ error: "Failed to get API key", detail: String(err) });
    }
  });

  app.patch("/admin/keys/:hash", requireAdmin, async (req: Request, res: Response) => {
    const { name, tier, enabled } = req.body;
    const updates: { name?: string; tier?: ApiKeyTier; enabled?: boolean } = {};

    if (name !== undefined) updates.name = name;
    if (tier !== undefined) {
      if (!["free", "pro", "enterprise"].includes(tier)) {
        return res.status(400).json({ error: "Invalid tier" });
      }
      updates.tier = tier;
    }
    if (enabled !== undefined) updates.enabled = Boolean(enabled);

    try {
      const success = await updateApiKey(req.params.hash, updates);
      if (!success) {
        return res.status(404).json({ error: "API key not found" });
      }
      return res.json({ success: true });
    } catch (err) {
      return res.status(500).json({ error: "Failed to update API key", detail: String(err) });
    }
  });

  app.delete("/admin/keys/:hash", requireAdmin, async (req: Request, res: Response) => {
    try {
      const success = await deleteApiKey(req.params.hash);
      if (!success) {
        return res.status(404).json({ error: "API key not found" });
      }
      return res.json({ success: true });
    } catch (err) {
      return res.status(500).json({ error: "Failed to delete API key", detail: String(err) });
    }
  });

  return app;
}
