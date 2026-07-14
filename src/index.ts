import { createApp } from "./app";
import { cacheManager } from "./CacheManager";
import { loadURLHaus } from "./checkers/urlHaus";
import { loadPhishTank } from "./checkers/phishtank";
import { loadOpenPhish } from "./checkers/openPhish";
import { loadPhishStats } from "./checkers/phishStats";
import { startContinuousFeeds } from "./feeds/continuous";
import { runWorkerLoop } from "./analysis/worker";
import { initCluster, shutdownClusterWorkers } from "./cluster";
import { hashApiKey, createApiKey } from "./utils/apiKeys";
import { verifyApiKey } from "./utils/apiKeys";
import cluster from "node:cluster";

// Initialize cluster: separates background tasks to Master, HTTP server to Workers
initCluster(startWorker, startMaster);

// Bootstrap the admin API key from env var
async function bootstrapAdminKey() {
  const adminKey = process.env.ADMIN_API_KEY;
  if (!adminKey) return;

  const existing = await verifyApiKey(adminKey);
  if (!existing) {
    try {
      await createApiKey("admin-bootstrap", "enterprise");
      console.log("Admin API key bootstrapped in Redis.");
    } catch (err) {
      console.error("Failed to bootstrap admin API key:", err);
    }
  }
}

// Master process background tasks
async function startMaster() {
  await bootstrapAdminKey();
  // Register background tasks (only if enabled)
  if ((process.env.ENABLE_FEEDS || "true").toLowerCase() !== "false") {
    cacheManager.addTask("urlhaus", loadURLHaus);
    cacheManager.addTask("phishtank", loadPhishTank);
    cacheManager.addTask("openphish", loadOpenPhish);
    cacheManager.addTask("phishstats", loadPhishStats);
    cacheManager.start(
      Number(process.env.CACHE_MANAGER_INTERVAL_MS) || undefined,
    );
  }

  // Start continuous poller (independent, smaller memory footprint)
  if (
    (process.env.ENABLE_CONTINUOUS_FEEDS || "false").toLowerCase() === "true"
  ) {
    startContinuousFeeds();
  }

  // Start worker only when explicitly enabled (useful on low-memory hosts)
  if ((process.env.ENABLE_WORKER || "false").toLowerCase() === "true") {
    runWorkerLoop();
  }

  // Master graceful shutdown
  const gracefulShutdownMaster = (signal: string) => {
    console.log(`Master received ${signal}. Shutting down gracefully...`);
    cacheManager.stop();
    shutdownClusterWorkers(signal as NodeJS.Signals);
    setTimeout(() => {
      console.log("Master shutdown complete.");
      process.exit(0);
    }, 10_000).unref();
  };

  process.on("SIGTERM", () => gracefulShutdownMaster("SIGTERM"));
  process.on("SIGINT", () => gracefulShutdownMaster("SIGINT"));
}

// Worker process HTTP server
function startWorker() {
  const app = createApp();
  const port = process.env.PORT || 4000;
  const server = app.listen(port, () =>
    console.log(`Phisherman worker ${process.pid} listening on ${port}`),
  );

  // Worker graceful shutdown
  const gracefulShutdownWorker = (signal: string) => {
    console.log(`Worker ${process.pid} received ${signal}. Draining connections...`);
    server.close(() => {
      console.log(`Worker ${process.pid} HTTP server closed. Exiting.`);
      process.exit(0);
    });
    // Force exit after 10s if connections refuse to drain
    setTimeout(() => {
      console.error(`Worker ${process.pid} forced shutdown after timeout.`);
      process.exit(1);
    }, 10_000).unref();
  };

  process.on("SIGTERM", () => gracefulShutdownWorker("SIGTERM"));
  process.on("SIGINT", () => gracefulShutdownWorker("SIGINT"));
}

// Prevent silent crashes -- log and survive unhandled rejections
process.on("unhandledRejection", (reason) => {
  console.error(`Unhandled promise rejection (PID: ${process.pid}):`, reason);
});

process.on("uncaughtException", (err) => {
  console.error(`Uncaught exception (PID: ${process.pid}):`, err);
  if (cluster.isWorker) {
    process.exit(1); // Master will restart it
  } else {
    process.exit(1);
  }
});
