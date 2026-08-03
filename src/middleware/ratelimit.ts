import { Request, Response, NextFunction } from "express";
import redis from "../utils/redis";

export const apiLimiter = async (req: Request, res: Response, next: NextFunction) => {
  const ip = req.ip || (req.headers["x-forwarded-for"] as string) || req.socket.remoteAddress;
  const key = `ratelimit:${ip}`;

  try {
    // Pipeline INCR + EXPIRE into a single HTTP round-trip
    const pipe = redis.pipeline();
    pipe.incr(key);
    pipe.expire(key, 900);
    const results = await pipe.exec();

    const requests = results[0] as number;

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
