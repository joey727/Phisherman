import axios from "axios";
import dotenv from "dotenv";

dotenv.config();

let phishDB: any[] | null = null;
let lastLoad = 0;


export async function loadPhishTank() {
  if (!phishDB || Date.now() - lastLoad > 3600 * 1000) {
    const r = await axios.get(process.env.PHISHTANK_API_URL!);
    phishDB = r.data;
    lastLoad = Date.now();
  }
  return phishDB;
}

export async function checkPhishTank(url: string) {
  try {
    const list: any = await loadPhishTank();
    const found = list.find((entry: any) => entry.url.includes(url));

    if (found) {
      return { score: 100, reason: "Listed in PhishTank database" };
    }
  } catch {}

  return { score: 0 };
}
