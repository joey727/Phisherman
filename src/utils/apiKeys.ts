import crypto from "node:crypto";
import redis from "./redis";
import { ApiKeyMetadata, ApiKeyTier } from "../types";

export function generateApiKey(): string {
  const bytes = crypto.randomBytes(48);
  const encoded = bytes
    .toString("base64url")
    .replace(/=/g, "");
  return `ph_${encoded}`;
}

export function hashApiKey(apiKey: string): string {
  return crypto.createHash("sha256").update(apiKey).digest("hex");
}

export async function createApiKey(
  name: string,
  tier: ApiKeyTier,
): Promise<{ apiKey: string; metadata: ApiKeyMetadata }> {
  const apiKey = generateApiKey();
  const hash = hashApiKey(apiKey);
  const prefix = apiKey.substring(0, 8);
  const createdAt = Date.now();

  await redis.hset(`apikey:${hash}`, {
    prefix,
    name,
    tier,
    enabled: "true",
    createdAt: String(createdAt),
    lastUsedAt: "",
  });
  await redis.zadd("apikeys", { score: createdAt, member: hash });

  return {
    apiKey,
    metadata: {
      hash,
      prefix,
      name,
      tier,
      enabled: true,
      createdAt,
      lastUsedAt: null,
    },
  };
}

export async function getApiKey(
  hash: string,
): Promise<ApiKeyMetadata | null> {
  const raw = await redis.hgetall(`apikey:${hash}`);
  if (!raw || Object.keys(raw).length === 0) return null;

  const data = raw as unknown as Record<string, string>;

  return {
    hash,
    prefix: data.prefix,
    name: data.name,
    tier: data.tier as ApiKeyTier,
    enabled: data.enabled === "true",
    createdAt: Number(data.createdAt),
    lastUsedAt: data.lastUsedAt ? Number(data.lastUsedAt) : null,
  };
}

export async function listApiKeys(): Promise<ApiKeyMetadata[]> {
  const hashes = await redis.zrange("apikeys", 0, -1);
  if (hashes.length === 0) return [];

  const results = await Promise.all(
    (hashes as string[]).map((hash) => getApiKey(hash)),
  );

  return results.filter((r): r is ApiKeyMetadata => r !== null);
}

export async function updateApiKey(
  hash: string,
  updates: { name?: string; tier?: ApiKeyTier; enabled?: boolean },
): Promise<boolean> {
  const exists = await redis.exists(`apikey:${hash}`);
  if (!exists) return false;

  const fields: Record<string, string> = {};
  if (updates.name !== undefined) fields.name = updates.name;
  if (updates.tier !== undefined) fields.tier = updates.tier;
  if (updates.enabled !== undefined) fields.enabled = String(updates.enabled);

  if (Object.keys(fields).length > 0) {
    await redis.hset(`apikey:${hash}`, fields);
  }

  return true;
}

export async function deleteApiKey(hash: string): Promise<boolean> {
  const exists = await redis.exists(`apikey:${hash}`);
  if (!exists) return false;

  await redis.del(`apikey:${hash}`);
  await redis.zrem("apikeys", hash);

  return true;
}

export async function verifyApiKey(
  apiKey: string,
): Promise<ApiKeyMetadata | null> {
  if (!apiKey.startsWith("ph_")) return null;

  const hash = hashApiKey(apiKey);
  const metadata = await getApiKey(hash);
  if (!metadata || !metadata.enabled) return null;

  const now = Date.now();
  await redis.hset(`apikey:${hash}`, { lastUsedAt: String(now) });

  return { ...metadata, lastUsedAt: now };
}
