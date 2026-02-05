import { Request, Response, NextFunction } from "express";
import redis from "../utils/redis";

export const apiLimiter = async (req: Request, res: Response, next: NextFunction) => {
  const ip = req.ip || (req.headers["x-forwarded-for"] as string) || req.socket.remoteAddress;
  const key = `ratelimit:${ip}`;

  try {
    const requests = await redis.incr(key);

    if (requests === 1) {
      await redis.expire(key, 900);
    }

    if (requests > 100) {
      return res.status(429).json({
        error: "Too many requests from this IP, please try again later.",
        limit: 100,
        current: requests
      });
    }

    next();
  } catch (err) {
    console.error("Rate limit check failed:", err);
    next();
  }
};
