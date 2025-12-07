import axios from "axios";

let cache: string[] = [];
let lastFetch = 0;

export async function checkOpenPhish(url: string) {
  try {
    // refresh cached feed every 15 minutes
    if (!cache || Date.now() - lastFetch > 15 * 60 * 1000) {
      const feed = await axios.get("https://openphish.com/feed.txt", {
        timeout: 5000,
      });

      cache = feed.data.split("\n").map((x: string) => x.trim());
      lastFetch = Date.now();
      console.log("OpenPhish feed loaded:", cache.length);
    }

    const exists = cache.some((phishUrl) => url.includes(phishUrl));

    if (exists) {
      return { score: 100, reason: "Listed in OpenPhish database" };
    }
  } catch (err) {
    console.error("OpenPhish error:", err);
  }

  return { score: 0 };
}
