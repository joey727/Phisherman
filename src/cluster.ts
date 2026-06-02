import cluster from "node:cluster";
import os from "node:os";

let shuttingDown = false;

/**
 * Initializes cluster mode.
 * Master process spawns workers (default: WEB_CONCURRENCY or 1).
 * Workers handle HTTP requests.
 */
export function initCluster(startWorker: () => void, startMaster: () => void) {
  if (cluster.isPrimary) {
    const numCPUs = os.cpus().length;
    const requestedWorkers = Number(process.env.WEB_CONCURRENCY) || 1;
    const workerCount = Math.max(1, Math.min(requestedWorkers, numCPUs));

    console.log(`Master process ${process.pid} is running`);
    console.log(`Starting ${workerCount} worker processes...`);

    // Master runs background tasks (cache refreshes)
    startMaster();

    // Fork workers
    for (let i = 0; i < workerCount; i++) {
      cluster.fork();
    }

    cluster.on("exit", (worker, code, signal) => {
      if (shuttingDown) return;

      console.warn(
        `Worker ${worker.process.pid} died (code: ${code}, signal: ${signal}). Restarting...`,
      );
      setTimeout(() => cluster.fork(), 1000);
    });
  } else {
    // Workers run the HTTP server
    startWorker();
  }
}

export function shutdownClusterWorkers(signal: NodeJS.Signals) {
  shuttingDown = true;

  for (const id in cluster.workers) {
    cluster.workers[id]?.process.kill(signal);
  }
}
