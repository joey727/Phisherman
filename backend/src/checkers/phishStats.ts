import axios from "axios";
import { URL } from "node:url";
import redis from "../utils/redis";
import { Checker, CheckResult } from "../types";

const FEED = "https://phishstats.info/phish_score.csv";
const REDIS_KEY_URLS = "phishstats_urls";
const REDIS_KEY_HOSTS = "phishstats_hosts";
const REDIS_KEY_LAST_UPDATE = "phishstats_last_update";

export async function loadPhishStats() {
    try {
        const lastUpdate = await redis.get(REDIS_KEY_LAST_UPDATE);
        const cacheExpired = !lastUpdate || (Date.now() - Number(lastUpdate) > 90 * 60 * 1000); // 90 mins

        if (cacheExpired) {
            console.log("PhishStats cache expired or missing. Refreshing Redis...");
            const response = await axios.get(FEED, { timeout: 45000 });

            const lines = response.data.split("\n");
            const tempUrlsKey = `${REDIS_KEY_URLS}_temp`;
            const tempHostsKey = `${REDIS_KEY_HOSTS}_temp`;

            await redis.del(tempUrlsKey);
            await redis.del(tempHostsKey);

            const urlBatch: string[] = [];
            const hostBatch: string[] = [];

            for (const line of lines) {
                if (line.startsWith("#") || line.trim().length === 0) continue;

                // Format: "date","score","url","ip"
                const parts = line.split(",");
                if (parts.length < 3) continue;

                const rawUrl = parts[2].replace(/"/g, "").trim();
                if (rawUrl) {
                    urlBatch.push(rawUrl);
                    try {
                        const u = new URL(rawUrl);
                        hostBatch.push(u.hostname);
                    } catch {
                        // ignore
                    }
                }

                if (urlBatch.length >= 1000) {
                    await (redis.sadd as any)(tempUrlsKey, ...urlBatch);
                    urlBatch.length = 0;
                }
                if (hostBatch.length >= 1000) {
                    await (redis.sadd as any)(tempHostsKey, ...hostBatch);
                    hostBatch.length = 0;
                }
            }

            if (urlBatch.length > 0) await (redis.sadd as any)(tempUrlsKey, ...urlBatch);
            if (hostBatch.length > 0) await (redis.sadd as any)(tempHostsKey, ...hostBatch);

            try {
                await (redis as any).rename(tempUrlsKey, REDIS_KEY_URLS);
                await (redis as any).rename(tempHostsKey, REDIS_KEY_HOSTS);
            } catch (renameErr) {
                // Handle case where temp keys were never created (empty feed)
                console.warn("PhishStats rename failed, likely empty feed data.");
            }

            await redis.set(REDIS_KEY_LAST_UPDATE, Date.now().toString());
            console.log(`PhishStats Redis cache updated.`);
        }
    } catch (err) {
        console.error("PhishStats refresh error:", err);
    }
}

export async function checkPhishStats(url: string): Promise<CheckResult> {
    try {
        const urlMatch = await redis.sismember(REDIS_KEY_URLS, url);
        if (urlMatch) return { score: 100, reason: "Listed in PhishStats database" };

        try {
            const u = new URL(url.startsWith("http") ? url : `http://${url}`);
            const hostMatch = await redis.sismember(REDIS_KEY_HOSTS, u.hostname);
            if (hostMatch) return { score: 80, reason: "Domain listed in PhishStats intelligence" };
        } catch {
            // ignore
        }
    } catch (err) {
        console.error("PhishStats check error:", err);
    }
    return { score: 0 };
}

export const PhishStatsChecker: Checker = {
    name: "phishstats",
    check: checkPhishStats,
};
