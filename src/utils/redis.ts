import { Redis } from "@upstash/redis";
import dotenv from "dotenv";

dotenv.config();

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
});

export async function setKey(
  key: string,
  value: string,
  expirationSeconds?: number
): Promise<void> {
  if (expirationSeconds) {
    await redis.setex(key, expirationSeconds, value);
  } else {
    await redis.set(key, value);
  }
}

export async function getKey(key: string): Promise<string | null> {
  return await redis.get(key);
}

export async function deleteKey(key: string): Promise<void> {
  await redis.del(key);
}

export default redis;
