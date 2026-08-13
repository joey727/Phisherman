import redis from "./utils/redis";
import { gsbCache, gwrCache, dnsCache } from "./utils/hashCache";

type RefreshTask = () => Promise<void>;

class CacheManager {
    private tasks: Map<string, RefreshTask> = new Map();
    private timeout: NodeJS.Timeout | null = null;
    private isRunning: boolean = false;
    private intervalMs: number = 3600000; // Default 1 hour

    addTask(name: string, task: RefreshTask) {
        this.tasks.set(name, task);
    }

    async start(intervalMs: number = 3600000) { 
        if (this.timeout) return;
        this.intervalMs = intervalMs;

        // Run once immediately
        await this.runAll();

        // Schedule next run
        this.scheduleNext();
    }

    private scheduleNext() {
        if (this.timeout) clearTimeout(this.timeout);
        this.timeout = setTimeout(() => {
            this.runAll().finally(() => this.scheduleNext());
        }, this.intervalMs);
    }

    async runAll() {
        if (this.isRunning) {
            console.warn("CacheManager: Already running. Skipping this cycle.");
            return;
        }
        this.isRunning = true;

        try {
            console.log("CacheManager: Starting background refreshes...");
            const entries = Array.from(this.tasks.entries());
            const results = await Promise.allSettled(
                entries.map(async ([name, task]) => {
                    console.log(`CacheManager: Refreshing ${name}...`);
                    await task();
                    console.log(`CacheManager: ${name} refresh complete.`);
                })
            );

            for (let i = 0; i < results.length; i++) {
                if (results[i].status === "rejected") {
                    console.error(`CacheManager: Task ${entries[i][0]} failed:`, (results[i] as PromiseRejectedResult).reason);
                }
            }

            // Cleanup tasks are lightweight -- run concurrently too
            await Promise.allSettled([
                this.cleanupScanResults(),
                this.cleanupWhois(),
                this.cleanupHashCaches(),
            ]);
            console.log("CacheManager: Background refreshes complete.");
        } catch (err) {
            console.error("CacheManager: RunAll general error:", err);
        } finally {
            this.isRunning = false;
        }
    }

    async cleanupScanResults() {
        const KEY_SCAN_HASH = "scan_results";
        const KEY_SCAN_EXPIRY = "scan_results_expiry";

        try {
            const now = Date.now();
            const expired = await redis.zrange(KEY_SCAN_EXPIRY, 0, now, { byScore: true });
            if (expired.length > 0) {
                const pipe = redis.pipeline();
                pipe.hdel(KEY_SCAN_HASH, ...(expired as string[]));
                pipe.zrem(KEY_SCAN_EXPIRY, ...expired);
                await pipe.exec();
            }
        } catch (err) {
            console.error("CacheManager: Scan-results cleanup failed:", err);
        }
    }

    async cleanupWhois() {
        const KEY_WHOIS_DATA = "whois_data";
        const KEY_WHOIS_EXPIRY = "whois_expiry";
        const KEY_RDAP_DATA = "rdap_data";
        const KEY_RDAP_EXPIRY = "rdap_expiry";

        try {
            const now = Date.now();
            // Get expired domains (score <= now)
            const expired = await redis.zrange(KEY_WHOIS_EXPIRY, 0, now, { byScore: true });
            const expiredRdap = await redis.zrange(KEY_RDAP_EXPIRY, 0, now, { byScore: true });

            if (expired.length > 0 || expiredRdap.length > 0) {
                console.log(
                    `CacheManager: Cleaning up ${expired.length} expired WHOIS entries and ${expiredRdap.length} expired RDAP entries...`,
                );
                const pipe = redis.pipeline();
                if (expired.length > 0) {
                    pipe.hdel(KEY_WHOIS_DATA, ...expired as string[]);
                    pipe.zrem(KEY_WHOIS_EXPIRY, ...expired);
                }
                if (expiredRdap.length > 0) {
                    pipe.hdel(KEY_RDAP_DATA, ...expiredRdap as string[]);
                    pipe.zrem(KEY_RDAP_EXPIRY, ...expiredRdap);
                }
                await pipe.exec();
                console.log("CacheManager: WHOIS/RDAP cleanup complete.");
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
        if (this.timeout) {
            clearTimeout(this.timeout);
            this.timeout = null;
        }
    }
}

export const cacheManager = new CacheManager();

