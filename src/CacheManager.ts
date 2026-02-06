import redis from "./utils/redis";
import { gsbCache, gwrCache, dnsCache } from "./utils/hashCache";

type RefreshTask = () => Promise<void>;

class CacheManager {
    private tasks: Map<string, RefreshTask> = new Map();
    private interval: NodeJS.Timeout | null = null;

    addTask(name: string, task: RefreshTask) {
        this.tasks.set(name, task);
    }

    async start(intervalMs: number = 3600000) { // Default 1 hour
        if (this.interval) return;

        // Run once immediately
        await this.runAll();

        this.interval = setInterval(() => this.runAll(), intervalMs);
    }

    async runAll() {
        console.log("CacheManager: Starting background refreshes...");
        for (const [name, task] of this.tasks.entries()) {
            try {
                console.log(`CacheManager: Refreshing ${name}...`);
                await task();
            } catch (err) {
                console.error(`CacheManager: Task ${name} failed:`, err);
            }
        }
        await this.cleanupScanResults();
        await this.cleanupWhois();
        await this.cleanupHashCaches();
        console.log("CacheManager: Background refreshes complete.");
    }

    async cleanupScanResults() {
        const KEY_SCAN_HASH = "scan_results";
        const KEY_SCAN_EXPIRY = "scan_results_expiry";

        try {
            const now = Date.now();
            const expired = await redis.zrange(KEY_SCAN_EXPIRY, 0, now, { byScore: true });
            if (expired.length > 0) {
                await redis.hdel(KEY_SCAN_HASH, ...(expired as string[]));
                await redis.zrem(KEY_SCAN_EXPIRY, ...expired);
            }
        } catch (err) {
            console.error("CacheManager: Scan-results cleanup failed:", err);
        }
    }

    async cleanupWhois() {
        const KEY_WHOIS_DATA = "whois_data";
        const KEY_WHOIS_EXPIRY = "whois_expiry";

        try {
            const now = Date.now();
            // Get expired domains (score <= now)
            const expired = await redis.zrange(KEY_WHOIS_EXPIRY, 0, now, { byScore: true });

            if (expired.length > 0) {
                console.log(`CacheManager: Cleaning up ${expired.length} expired WHOIS entries...`);
                // Remove from Hash
                await redis.hdel(KEY_WHOIS_DATA, ...expired as string[]);
                // Remove from ZSET
                await redis.zrem(KEY_WHOIS_EXPIRY, ...expired);
                console.log("CacheManager: WHOIS cleanup complete.");
            }
        } catch (err) {
            console.error("CacheManager: WHOIS cleanup failed:", err);
        }
    }

    async cleanupHashCaches() {
        try {
            const gsbCleaned = await gsbCache.cleanup();
            const gwrCleaned = await gwrCache.cleanup();
            const dnsCleaned = await dnsCache.cleanup();
            const total = gsbCleaned + gwrCleaned + dnsCleaned;
            if (total > 0) {
                console.log(`CacheManager: Cleaned up ${total} expired hash cache entries (GSB:${gsbCleaned}, GWR:${gwrCleaned}, DNS:${dnsCleaned})`);
            }
        } catch (err) {
            console.error("CacheManager: Hash cache cleanup failed:", err);
        }
    }

    stop() {
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
        }
    }
}

export const cacheManager = new CacheManager();
