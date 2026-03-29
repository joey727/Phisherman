import redis from "./redis";
import crypto from "node:crypto";

/**
 * A hash-based cache that stores entries in a single Redis hash plus a ZSET for expiry tracking.
 * This avoids key explosion while still allowing per-entry TTL management.
 * All compound Redis operations use pipelines to minimize HTTP round-trips (important for Upstash).
 */
export class HashCache {
    private readonly hashKey: string;
    private readonly expiryKey: string;
    private readonly defaultTtlSeconds: number;

    constructor(name: string, defaultTtlSeconds: number = 3600) {
        this.hashKey = `${name}_hash`;
        this.expiryKey = `${name}_expiry`;
        this.defaultTtlSeconds = defaultTtlSeconds;
    }

    /** Create a stable, short field ID from a potentially long key */
    private fieldId(key: string): string {
        return crypto.createHash("sha256").update(key).digest("hex").slice(0, 32);
    }

    async get<T>(key: string): Promise<T | null> {
        const fieldId = this.fieldId(key);
        try {
            const raw = await redis.hget(this.hashKey, fieldId);
            if (!raw) return null;

            const entry = typeof raw === "string" ? JSON.parse(raw) : raw;
            if (entry?.exp && entry.exp > Date.now() && entry.value !== undefined) {
                return entry.value as T;
            }

            // Expired - opportunistically clean up (pipelined)
            const pipe = redis.pipeline();
            pipe.hdel(this.hashKey, fieldId);
            pipe.zrem(this.expiryKey, fieldId);
            await pipe.exec();
            return null;
        } catch (err) {
            return null;
        }
    }

    async set<T>(key: string, value: T, ttlSeconds?: number): Promise<void> {
        const fieldId = this.fieldId(key);
        const ttl = ttlSeconds ?? this.defaultTtlSeconds;
        const exp = Date.now() + ttl * 1000;

        try {
            const pipe = redis.pipeline();
            pipe.hset(this.hashKey, { [fieldId]: JSON.stringify({ exp, value }) });
            pipe.zadd(this.expiryKey, { score: exp, member: fieldId });
            await pipe.exec();
        } catch (err) {
            console.error(`HashCache set error for ${this.hashKey}:`, err);
        }
    }

    async delete(key: string): Promise<void> {
        const fieldId = this.fieldId(key);
        try {
            const pipe = redis.pipeline();
            pipe.hdel(this.hashKey, fieldId);
            pipe.zrem(this.expiryKey, fieldId);
            await pipe.exec();
        } catch (err) {
            console.error(`HashCache delete error for ${this.hashKey}:`, err);
        }
    }

    /** Clean up all expired entries - call periodically from CacheManager */
    async cleanup(): Promise<number> {
        try {
            const now = Date.now();
            const expired = await redis.zrange(this.expiryKey, 0, now, { byScore: true });
            if (expired.length > 0) {
                const pipe = redis.pipeline();
                pipe.hdel(this.hashKey, ...(expired as string[]));
                pipe.zrem(this.expiryKey, ...expired);
                await pipe.exec();
                return expired.length;
            }
        } catch (err) {
            console.error(`HashCache cleanup error for ${this.hashKey}:`, err);
        }
        return 0;
    }
}

// Pre-configured caches for different data types
export const gsbCache = new HashCache("gsb_cache", 3600); // Google Safe Browsing - 1 hour
export const gwrCache = new HashCache("gwr_cache", 3600); // Google Web Risk - 1 hour  
export const dnsCache = new HashCache("dns_cache", 3600); // DNS resolution - 1 hour

