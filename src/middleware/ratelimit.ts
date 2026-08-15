import { Request, Response, NextFunction } from "express";
import redis from "../utils/redis";
import { TIER_CONFIGS } from "../types";

const ANON_MAX_CONCURRENT =
  Number(process.env.MAX_CONCURRENT_REQUESTS_PER_IP) || 1;
const ANON_WINDOW_SECONDS = Number(process.env.RATE_LIMIT_WINDOW_SECONDS) || 86400;
const ANON_MAX_REQUESTS = Number(process.env.RATE_LIMIT_MAX_REQUESTS) || 1;
const concurrentByKey = new Map<string, number>();

export const apiLimiter = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const identity = req.apiKey
    ? `key:${req.apiKey.hash}`
    : req.ip ||
      (req.headers["x-forwarded-for"] as string) ||
      req.socket.remoteAddress ||
      "unknown";

  const tierConfig = req.apiKey
    ? TIER_CONFIGS[req.apiKey.tier]
    : {
        maxConcurrent: ANON_MAX_CONCURRENT,
        windowSeconds: ANON_WINDOW_SECONDS,
        maxRequests: ANON_MAX_REQUESTS,
      };

  // 1. In-memory concurrent request limit
  const currentConcurrent = concurrentByKey.get(identity) || 0;
  if (currentConcurrent >= tierConfig.maxConcurrent) {
    return res.status(429).json({
      error: "Too many concurrent requests",
      limit: tierConfig.maxConcurrent,
    });
  }

  concurrentByKey.set(identity, currentConcurrent + 1);
  let cleanedUp = false;
  const cleanup = () => {
    if (cleanedUp) return;
    cleanedUp = true;
    const active = concurrentByKey.get(identity) || 0;
    if (active > 1) {
      concurrentByKey.set(identity, active - 1);
    } else {
      concurrentByKey.delete(identity);
    }
    res.removeListener("finish", cleanup);
    res.removeListener("close", cleanup);
  };
  res.on("finish", cleanup);
  res.on("close", cleanup);

  // 2. Anonymous (no API key) requests are free: no windowed quota. They still
  // share the per-IP concurrent cap above to protect the server from floods.
  if (!req.apiKey) {
    return next();
  }

  // 3. Rate limit via Redis (authenticated keys only)
  const redisKey = `ratelimit:${identity}`;

  try {
    const pipe = redis.pipeline();
    pipe.incr(redisKey);
    pipe.expire(redisKey, tierConfig.windowSeconds);
    const results = await pipe.exec();

    const requests = results[0] as number;

    if (requests > tierConfig.maxRequests) {
      // Quota exhausted: don't reject — degrade this request to the free/
      // anonymous quality set (heuristics only, no ML) for the rest of the
      // window. The counter keeps counting so the key stays degraded.
      req.degradedQuota = true;
      res.setHeader("X-RateLimit-Limit", String(tierConfig.maxRequests));
      res.setHeader("X-RateLimit-Remaining", "0");
      res.setHeader("X-RateLimit-Reset", String(tierConfig.windowSeconds));
      return next();
    }

    res.setHeader("X-RateLimit-Limit", String(tierConfig.maxRequests));
    res.setHeader(
      "X-RateLimit-Remaining",
      String(Math.max(0, tierConfig.maxRequests - requests)),
    );
    res.setHeader("X-RateLimit-Reset", String(tierConfig.windowSeconds));

    next();
  } catch (err) {
    console.error("Rate limit check failed:", err);
    next();
  }
};
