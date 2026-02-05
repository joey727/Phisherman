import express, { Request, Response } from "express";
import cors from "cors";
import { analyzeUrl } from "./Scanner";
import { apiLimiter } from "./middleware/ratelimit";
import { cacheManager } from "./CacheManager";
import { loadURLHaus } from "./checkers/urlHaus";
import { loadPhishTank } from "./checkers/phishtank";
import { loadOpenPhish } from "./checkers/openPhish";
import { loadPhishStats } from "./checkers/phishStats";

const app = express();
app.set("trust proxy", 1);
app.use(express.json());
app.use(cors());
app.use(apiLimiter);

// Register background tasks
cacheManager.addTask("urlhaus", loadURLHaus);
cacheManager.addTask("phishtank", loadPhishTank);
cacheManager.addTask("openphish", loadOpenPhish);
cacheManager.addTask("phishstats", loadPhishStats);
cacheManager.start();

app.post("/api/check", async (req: Request, res: Response) => {
  const { url } = req.body;
  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Missing 'url' in body" });
  }

  try {
    const result = await analyzeUrl(url);
    return res.json(result);
  } catch (err) {
    console.error("analyze error:", err);
    return res.status(500).json({ error: "Server error", detail: String(err) });
  }
});

const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`Phisherman backend listening on ${port}`));
