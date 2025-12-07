import axios from "axios";
import dotenv from "dotenv";
import { URL } from "node:url";

dotenv.config();

let phishDB: any[] = [];
let lastLoad = 0;

export async function loadPhishTank() {
  try {
    if (!phishDB || Date.now() - lastLoad > 3600 * 1000) {
      const r = await axios.get(process.env.PHISHTANK_API_URL!);
      phishDB = r.data;
      lastLoad = Date.now();
      console.log("PhishTank DB loaded:", phishDB.length);
    }
    
  } catch (err) {
    console.error("PhishTank fetch error:", err);
    phishDB = [];
  }

  return phishDB || [];
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
    const list = await loadPhishTank();
    const targetHost = normalize(url);

    for (const entry of list) {
      if (!entry.url) continue;

      const entryHost = normalize(entry.url);

      // Hostname match (strong signal)
      if (targetHost === entryHost) {
        return {
          score: 100,
          reason: "Exact domain match in PhishTank",
        };
      }

      // Partial match (redirect or subpath phishing)
      if (url.includes(entry.url) || entry.url.includes(url)) {
        return {
          score: 80,
          reason: "URL appears in PhishTank list (partial match)",
        };
      }
    }
  } catch (err) {
    console.error("PhishTank check error:", err);
  }

  return { score: 0 };
}

