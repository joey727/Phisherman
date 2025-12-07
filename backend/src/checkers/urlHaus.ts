// src/checkers/urlHaus.ts
import axios from "axios";

let urlhausCache: any[] = [];
let lastLoad = 0;
const FEED = "https://urlhaus.abuse.ch/downloads/json/";

export async function loadURLHaus() {
  const expired = Date.now() - lastLoad > 3600 * 1000;

  if (!urlhausCache || expired) {
    try {
      const r = await axios.get(FEED, {
        timeout: 20000,
        decompress: false, // prevents stream abort
        responseType: "json",
        headers: { "Accept-Encoding": "identity" } // avoid gzip issues
      });

      if (r.data?.urls && Array.isArray(r.data.urls)) {
        urlhausCache = r.data.urls;
        lastLoad = Date.now();
        console.log("URLHaus feed loaded:", urlhausCache.length);
      } else {
        console.warn("URLHaus JSON format invalid");
        urlhausCache = [];
      }
    } catch (err) {
      console.error("URLHaus download error:", err);
      urlhausCache = []; // fail open
    }
  }

  return urlhausCache;
}

export async function checkURLHaus(url: string) {
  const data = await loadURLHaus();
  if (!data) return { score: 0 };

  const found = data.find((e: any) => e.url === url);

  if (found) {
    return {
      score: 100,
      reason: "URL matches URLHaus phishing/malware list",
      details: found
    };
  }

  return { score: 0 };
}
