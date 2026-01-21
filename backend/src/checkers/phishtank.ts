import axios from "axios";
import dotenv from "dotenv";
import { URL } from "node:url";
import redis from "../utils/redis";
import pako from "pako";

dotenv.config();

const REDIS_KEY_URLS = "phishtank_urls";
// const REDIS_KEY_HOSTS = "phishtank_hosts";
const REDIS_KEY_LAST_UPDATE = "phishtank_last_update";
const REDIS_KEY_LAST_FAIL = "phishtank_last_fail";
const FAIL_COOLDOWN_MS = 15 * 60 * 1000; // back off for 15 minutes after a failed fetch
const MAX_FEED_BYTES = 100 * 1024 * 1024; // hard cap on feed size to avoid memory blowups

const DEFAULT_PHISHTANK_URLS = [
  "https://data.phishtank.com/data/online-valid.json.gz",
  "https://data.phishtank.com/data/online-valid.json",
];

export async function loadPhishTank() {
  try {
    const lastUpdate = await redis.get(REDIS_KEY_LAST_UPDATE);
    const cacheExpired = !lastUpdate || (Date.now() - Number(lastUpdate) > 3600 * 1000);

    if (cacheExpired) {
      const lastFail = await redis.get(REDIS_KEY_LAST_FAIL);
      const failedRecently = lastFail && (Date.now() - Number(lastFail) < FAIL_COOLDOWN_MS);
      if (failedRecently) {
        console.log("Skipping PhishTank refresh due to recent failure cooldown.");
        return;
      }

      console.log("PhishTank cache expired or missing. Refreshing Redis...");
      const normalizeCandidate = (url: string) => {
        // Only append format=json if it's not already present and the URL is not a gzipped dump.
        if (!url.includes("format=json") && !url.endsWith(".gz")) {
          const separator = url.includes("?") ? "&" : "?";
          return `${url}${separator}format=json`;
        }
        return url;
      };

      const candidates = [
        process.env.PHISHTANK_API_URL
          ? normalizeCandidate(process.env.PHISHTANK_API_URL)
          : undefined,
        ...DEFAULT_PHISHTANK_URLS,
      ].filter(Boolean) as string[];

      try {
        let data: any;
        let rawString = "";
        let succeeded = false;

        for (const candidate of candidates) {
          console.log(`Fetching PhishTank from: ${candidate}`);
          try {
            const response = await axios.get(candidate, {
              timeout: 30000,
              headers: { "User-Agent": "phishtank/PhishermanScanner" },
              responseType: "arraybuffer",
              maxContentLength: 100 * 1024 * 1024, // allow larger feed payloads
              maxBodyLength: 100 * 1024 * 1024,
              decompress: true,
              validateStatus: (status) => status >= 200 && status < 300,
            });

            const status = response?.status;
            if (typeof status !== "number") {
              throw new Error("PhishTank response missing status code");
            }
            console.log(`PhishTank API status: ${status}`);

            const headers = (response as any)?.headers || {};
            const contentType = headers["content-type"] || headers["Content-Type"];
            if (contentType && contentType.startsWith("image/")) {
              throw new Error(`Unexpected content-type from PhishTank: ${contentType}`);
            }

            const buffer = Buffer.from(response.data ?? []);

            if (buffer.length > MAX_FEED_BYTES) {
              console.error(
                `PhishTank feed too large (${buffer.length} bytes > ${MAX_FEED_BYTES}); aborting parse.`
              );
              throw new Error("PhishTank feed exceeded maximum allowed size");
            }

            if (buffer[0] === 0x1f && buffer[1] === 0x8b) {
              rawString = pako.inflate(new Uint8Array(buffer), { to: "string" });
            } else {
              rawString = buffer.toString();
            }

            try {
              data = JSON.parse(rawString);
              console.log(`PhishTank parsed successfully. Total entries: ${Array.isArray(data) ? data.length : 0}`);
              succeeded = true;
              break;
            } catch (parseError) {
              console.error("Failed to parse PhishTank response as JSON.");
              console.error(`First 200 chars of response: ${rawString.substring(0, 200)}`);
              throw new Error(`PhishTank API returned invalid JSON: ${parseError}`);
            }
          } catch (candidateErr) {
            console.error(`PhishTank fetch failed for ${candidate}:`, candidateErr);
          }
        }

        if (!succeeded) {
          await redis.set(REDIS_KEY_LAST_FAIL, Date.now().toString());
          throw new Error("All PhishTank endpoints failed; backing off.");
        } else {
          await redis.del(REDIS_KEY_LAST_FAIL);
        }

        if (Array.isArray(data) && data.length > 0) {
          console.log("PhishTank Sample Entry:", JSON.stringify(data[0], null, 2));

          const urls: string[] = [];
          const hosts: Set<string> = new Set();

          data.forEach((entry: any) => {
            if (entry.url) {
              urls.push(entry.url);
              try {
                const host = new URL(entry.url).hostname.replace("www.", "").toLowerCase();
                if (host) hosts.add(host);
              } catch {
                // Ignore invalid URLs
              }
            }
          });

          if (urls.length > 0) {
            await redis.del(REDIS_KEY_URLS);

            const batchSize = 1000;
            for (let i = 0; i < urls.length; i += batchSize) {
              await (redis as any).sadd(REDIS_KEY_URLS, ...urls.slice(i, i + batchSize));
            }

            await redis.set(REDIS_KEY_LAST_UPDATE, Date.now().toString());
            console.log(`PhishTank Redis cache populated: ${urls.length} URLs.`);
          } else {
            console.warn("PhishTank response contained no URL entries; leaving cache unchanged.");
          }
        }
      } catch (err) {
        console.error("PhishTank refresh error:", err);
      }
    }
  } catch (err) {
    console.error("PhishTank refresh error:", err);
  }
}

function normalize(u: string): string {
  try {
    return new URL(u).hostname.replace("www.", "").toLowerCase();
  } catch {
    return u.toLowerCase();
  }
}

export async function checkPhishTank(url: string) {
  try {
    const setExists = await redis.exists(REDIS_KEY_URLS);
    if (!setExists) {
      await loadPhishTank();
    } else {
      // Trigger background refresh if needed without blocking
      loadPhishTank().catch(e => console.error("Background PhishTank refresh failed:", e));
    }

    // Exact URL Match
    const isUrlMember = await redis.sismember(REDIS_KEY_URLS, url);
    if (isUrlMember) {
      return {
        score: 100,
        reason: "Exact URL match in PhishTank database",
      };
    }

    // Hostname Match
    // const targetHost = normalize(url);
    // const isHostMember = await redis.sismember(REDIS_KEY_HOSTS, targetHost);
    // if (isHostMember) {
    //   return {
    //     score: 100,
    //     reason: "Domain match in PhishTank (phishing host)",
    //   };
    // }

  } catch (err) {
    console.error("PhishTank check error:", err);
  }

  return { score: 0 };
}

