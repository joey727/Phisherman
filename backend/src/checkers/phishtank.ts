import axios from "axios";
import dotenv from "dotenv";
import { URL } from "node:url";
import redis from "../utils/redis";
import pako from "pako";

dotenv.config();

const REDIS_KEY_URLS = "phishtank_urls";
const REDIS_KEY_HOSTS = "phishtank_hosts";
const REDIS_KEY_LAST_UPDATE = "phishtank_last_update";

export async function loadPhishTank() {
  try {
    const lastUpdate = await redis.get(REDIS_KEY_LAST_UPDATE);
    const cacheExpired = !lastUpdate || (Date.now() - Number(lastUpdate) > 3600 * 1000);

    if (cacheExpired) {
      console.log("PhishTank cache expired or missing. Refreshing Redis...");
      let apiUrl = process.env.PHISHTANK_API_URL!;
      if (!apiUrl.includes("format=json")) {
        apiUrl += (apiUrl.includes("?") ? "&" : "?") + "format=json";
      }

      console.log(`Fetching PhishTank from: ${apiUrl}`);

      const response = await axios.get(apiUrl, {
        timeout: 60000,
        headers: { "User-Agent": "phishtank/PhishermanScanner" },
        responseType: "arraybuffer", // Important for receiving binary data
        maxContentLength: Infinity,
        maxBodyLength: Infinity,
        decompress: true
      });

      console.log(`PhishTank API status: ${response.status}`);
      let data: any;
      const buffer = Buffer.from(response.data);
      let rawString = "";

      // Check for GZIP magic numbers (1f 8b)
      if (buffer[0] === 0x1f && buffer[1] === 0x8b) {
        console.log("Decompressing PhishTank GZIP data...");
        rawString = pako.inflate(new Uint8Array(buffer), { to: "string" });
      } else {
        rawString = buffer.toString();
      }

      try {
        data = JSON.parse(rawString);
        console.log(`PhishTank parsed successfully. Total entries: ${Array.isArray(data) ? data.length : 0}`);
      } catch (parseError) {
        console.error("Failed to parse PhishTank response as JSON.");
        console.error(`First 200 chars of response: ${rawString.substring(0, 200)}`);
        throw new Error(`PhishTank API returned invalid JSON: ${parseError}`);
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
          await redis.del(REDIS_KEY_URLS, REDIS_KEY_HOSTS);

          const batchSize = 1000;
          for (let i = 0; i < urls.length; i += batchSize) {
            await (redis as any).sadd(REDIS_KEY_URLS, ...urls.slice(i, i + batchSize));
          }
          const hostArray = Array.from(hosts);
          for (let i = 0; i < hostArray.length; i += batchSize) {
            await (redis as any).sadd(REDIS_KEY_HOSTS, ...hostArray.slice(i, i + batchSize));
          }

          await redis.set(REDIS_KEY_LAST_UPDATE, Date.now().toString());
          console.log(`PhishTank Redis cache populated: ${urls.length} URLs, ${hostArray.length} Hosts.`);
        }
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
    const targetHost = normalize(url);
    const isHostMember = await redis.sismember(REDIS_KEY_HOSTS, targetHost);
    if (isHostMember) {
      return {
        score: 100,
        reason: "Domain match in PhishTank (phishing host)",
      };
    }

  } catch (err) {
    console.error("PhishTank check error:", err);
  }

  return { score: 0 };
}

