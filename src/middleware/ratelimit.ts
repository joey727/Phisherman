import { Request, Response, NextFunction } from "express";
import redis from "../utils/redis";

const MAX_CONCURRENT_PER_IP =
  Number(process.env.MAX_CONCURRENT_REQUESTS_PER_IP) || 10;
const WINDOW_SECONDS = Number(process.env.RATE_LIMIT_WINDOW_SECONDS) || 900;
const MAX_REQUESTS_PER_WINDOW =
  Number(process.env.RATE_LIMIT_MAX_REQUESTS) || 100;
const concurrentByIp = new Map<string, number>();

export const apiLimiter = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  const ip =
    req.ip ||
    (req.headers["x-forwarded-for"] as string) ||
    req.socket.remoteAddress ||
    "unknown_ip";

  // 1. In-memory concurrent request limit per IP
  const currentConcurrent = concurrentByIp.get(ip) || 0;
  if (currentConcurrent >= MAX_CONCURRENT_PER_IP) {
    return res.status(429).json({
      error: "Too many concurrent requests from this IP",
      limit: MAX_CONCURRENT_PER_IP,
    });
  }

  concurrentByIp.set(ip, currentConcurrent + 1);
  let cleanedUp = false;
  const cleanup = () => {
    if (cleanedUp) return;
    cleanedUp = true;
    const active = concurrentByIp.get(ip) || 0;
    if (active > 1) {
      concurrentByIp.set(ip, active - 1);
    } else {
      concurrentByIp.delete(ip);
    }
    res.removeListener("finish", cleanup);
    res.removeListener("close", cleanup);
  };
  res.on("finish", cleanup);
  res.on("close", cleanup);

  // 2. Global rate limit via Redis
  const key = `ratelimit:${ip}`;

  try {
    // Pipeline INCR + EXPIRE into a single HTTP round-trip
    const pipe = redis.pipeline();
    pipe.incr(key);
    pipe.expire(key, WINDOW_SECONDS);
    const results = await pipe.exec();

    const requests = results[0] as number;

    if (requests > MAX_REQUESTS_PER_WINDOW) {
      return res.status(429).json({
        error: "Too many requests from this IP, please try again later.",
        limit: MAX_REQUESTS_PER_WINDOW,
        current: requests,
      });
    }

    next();
  } catch (err) {
    console.error("Rate limit check failed:", err);
    next();
  }
};
