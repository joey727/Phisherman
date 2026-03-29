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

// Register background tasks
cacheManager.addTask("urlhaus", loadURLHaus);
cacheManager.addTask("phishtank", loadPhishTank);
cacheManager.addTask("openphish", loadOpenPhish);
cacheManager.addTask("phishstats", loadPhishStats);
cacheManager.start();

// Health check endpoint (Render uses this to verify the service is alive)
app.get("/health", (_req: Request, res: Response) => {
  return res.json({ status: "ok" });
});

// Rate limiter scoped to the scan endpoint only (avoids Redis overhead on health checks)
app.post("/api/check", apiLimiter, async (req: Request, res: Response) => {
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
const server = app.listen(port, () => console.log(`Phisherman backend listening on ${port}`));

// Graceful shutdown 
function gracefulShutdown(signal: string) {
  console.log(`Received ${signal}. Shutting down gracefully...`);
  cacheManager.stop();
  server.close(() => {
    console.log("HTTP server closed. Exiting.");
    process.exit(0);
  });
  // Force exit after 10s if server.close() hangs
  setTimeout(() => {
    console.error("Forced shutdown after timeout.");
    process.exit(1);
  }, 10_000).unref();
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

// Prevent silent crashes -- log and survive unhandled rejections
process.on("unhandledRejection", (reason) => {
  console.error("Unhandled promise rejection:", reason);
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught exception:", err);
  gracefulShutdown("uncaughtException");
});
