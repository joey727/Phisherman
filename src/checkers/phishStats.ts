import axios from "axios";
import { URL } from "node:url";
import redis from "../utils/redis";
import { Checker, CheckResult, ParsedUrl } from "../types";
import { isTrustedApex } from "../utils/trustedApex";

// The API caps `_size` at 100 rows per request and ignores any larger value,
// so the feed must be fetched with `_p` pagination. `_sort=-id` returns the
// newest first. Docs: https://phishstats.info/api-docs
const BASE = "https://api.phishstats.info/api/phishing";
const REDIS_KEY_URLS = "phishstats_urls";
const REDIS_KEY_HOSTS = "phishstats_hosts";
const REDIS_KEY_LAST_UPDATE = "phishstats_last_update";

export async function loadPhishStats() {
    // Anonymous access is limited to 50 requests/day/IP; a psk_* key raises the
    // quota. We refresh roughly every 90 minutes (~16x/day), so the per-refresh
    // page budget keeps daily usage within the anonymous limit unless a key is set.
    const apiKey = process.env.PHISHSTATS_API_KEY || "";
    const maxPages = Number(process.env.PHISHSTATS_MAX_PAGES) || (apiKey ? 10 : 3);
    try {
        const lastUpdate = await redis.get(REDIS_KEY_LAST_UPDATE);
        const cacheExpired = !lastUpdate || (Date.now() - Number(lastUpdate) > 90 * 60 * 1000); // 90 mins

        if (cacheExpired) {
            console.log("PhishStats cache expired or missing. Refreshing Redis...");
            // Add heavy user-agent to avoid blind blocking
            const headers: Record<string, string> = { "User-Agent": "Phisherman/1.0" };
            if (apiKey) headers["X-API-Key"] = apiKey;

            const entries: Array<{ id: number; url?: string }> = [];
            for (let page = 1; page <= maxPages; page++) {
                const res = await axios.get(
                    `${BASE}?_sort=-id&_size=100&_p=${page}`,
                    { timeout: 45000, headers },
                );
                const rows = res.data;
                if (!Array.isArray(rows)) {
                    console.warn("PhishStats API returned non-array data");
                    break;
                }
                entries.push(...rows);
                // Newest-first pages fill up with 100 rows until the feed ends.
                if (rows.length < 100) break;
                await new Promise(resolve => setImmediate(resolve));
            }

            if (entries.length === 0) {
                console.warn("PhishStats feed returned 0 entries; keeping previous cache.");
                return;
            }

            const tempUrlsKey = `${REDIS_KEY_URLS}_temp`;
            const tempHostsKey = `${REDIS_KEY_HOSTS}_temp`;

            await redis.del(tempUrlsKey);
            await redis.del(tempHostsKey);

            const urlBatch: string[] = [];
            const hostBatch: string[] = [];

            for (const entry of entries) {
                if (!entry.url) continue;

                const rawUrl = entry.url.trim();
                urlBatch.push(rawUrl);
                try {
                    const u = new URL(rawUrl);
                    hostBatch.push(u.hostname);
                } catch {
                    // ignore invalid URLs in feed
                }

                if (urlBatch.length >= 1000) {
                    await (redis.sadd as any)(tempUrlsKey, ...urlBatch);
                    urlBatch.length = 0;
                    await new Promise(resolve => setImmediate(resolve));
                }
                if (hostBatch.length >= 1000) {
                    await (redis.sadd as any)(tempHostsKey, ...hostBatch);
                    hostBatch.length = 0;
                    await new Promise(resolve => setImmediate(resolve));
                }
            }

            if (urlBatch.length > 0) await (redis.sadd as any)(tempUrlsKey, ...urlBatch);
            if (hostBatch.length > 0) await (redis.sadd as any)(tempHostsKey, ...hostBatch);

            try {
                await (redis as any).rename(tempUrlsKey, REDIS_KEY_URLS);
                await (redis as any).rename(tempHostsKey, REDIS_KEY_HOSTS);
            } catch (err) {
                console.warn("PhishStats rename failed, likely empty feed data.", err);
                return;
            }

            await redis.set(REDIS_KEY_LAST_UPDATE, Date.now().toString());
            console.log(`PhishStats Redis cache updated with ${entries.length} entries.`);
        }
    } catch (err) {
        // Non-2xx (e.g. 429 rate limit) or network errors: keep the previously
        // cached data and log. Never discard valid data on a failed refresh.
        console.error("PhishStats refresh error:", err);
    }
}

export async function checkPhishStats(url: string, parsed?: ParsedUrl): Promise<CheckResult> {
    try {
        const urlMatch = await redis.sismember(REDIS_KEY_URLS, url);
        if (urlMatch) return { score: 100, reason: "Listed in PhishStats database" };

        // Use pre-parsed hostname if available
        const hostname = parsed?.hostname;
        const hostNames = hostname
            ? [hostname]
            : (() => {
                try {
                    const u = new URL(url.startsWith("http") ? url : `http://${url}`);
                    return [u.hostname];
                } catch {
                    return [];
                }
            })();

        for (const h of hostNames) {
            // Skip host-level match on trusted official apexes (the exact URL
            // match above still catches real phishing on those apexes).
            if (isTrustedApex(h)) continue;
            const hostMatch = await redis.sismember(REDIS_KEY_HOSTS, h);
            if (hostMatch) return { score: 80, reason: "Domain listed in PhishStats intelligence" };
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
