import { loadURLHaus } from "../checkers/urlHaus";
import { loadPhishTank } from "../checkers/phishtank";
import { loadOpenPhish } from "../checkers/openPhish";
import { loadPhishStats } from "../checkers/phishStats";

const DEFAULT_POLL_MS = Number(process.env.FEED_POLL_MS) || 60_000; // 1 minute

export function startContinuousFeeds() {
  if ((process.env.ENABLE_CONTINUOUS_FEEDS || "true").toLowerCase() === "false")
    return;

  console.log("Starting continuous feed poller");

  setInterval(async () => {
    try {
      await Promise.allSettled([
        loadURLHaus(),
        loadPhishTank(),
        loadOpenPhish(),
        loadPhishStats(),
      ]);
    } catch (err) {
      console.warn("continuous feed poller error:", String(err));
    }
  }, DEFAULT_POLL_MS).unref();
}
