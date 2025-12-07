import axios from "axios";

let urlhausCache: any[] = [];
let lastLoad = 0;
const FEED = "https://urlhaus.abuse.ch/downloads/json_recent/";

export async function loadURLHaus() {
  const cacheExpired = Date.now() - lastLoad > 3600 * 1000; // refresh every hour

  if (!urlhausCache || cacheExpired) {
    try {
      const response = await axios.get(FEED, {
        timeout: 30000,
        responseType: "stream",
        headers: { "User-Agent": "PhishermanScanner/1.0" }, // avoid gzip streaming issues
      });

      let data = "";
      for await (const chunk of response.data) {
        data += chunk.toString();
      }
      console.log("URLHaus feed downloaded, size:", data.length);
      const json = JSON.parse(data);
      return json.urls || [];
    } catch (err) {
      console.error("URLHaus download error:", err);
      return [];
    }
  }

  return urlhausCache;
}

export async function checkURLHaus(url: string) {
  const data = await loadURLHaus();
  if (!data || data.length === 0) return { score: 0 };

  const found = data.find((entry: any) => entry.url === url);

  if (found) {
    return {
      score: 100,
      reason: "URL matches URLHaus recent feed (malware/phishing)",
      details: found,
    };
  }

  return { score: 0 };
}
