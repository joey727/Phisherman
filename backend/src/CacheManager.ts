import redis from "./utils/redis";

type RefreshTask = () => Promise<void>;

class CacheManager {
    private tasks: Map<string, RefreshTask> = new Map();
    private interval: NodeJS.Timeout | null = null;

    addTask(name: string, task: RefreshTask) {
        this.tasks.set(name, task);
    }

    async start(intervalMs: number = 3600000) { // Default 1 hour
        if (this.interval) return;

        // Run once immediately
        await this.runAll();

        this.interval = setInterval(() => this.runAll(), intervalMs);
    }

    async runAll() {
        console.log("CacheManager: Starting background refreshes...");
        for (const [name, task] of this.tasks.entries()) {
            try {
                console.log(`CacheManager: Refreshing ${name}...`);
                await task();
            } catch (err) {
                console.error(`CacheManager: Task ${name} failed:`, err);
            }
        }
        console.log("CacheManager: Background refreshes complete.");
    }

    stop() {
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
        }
    }
}

export const cacheManager = new CacheManager();
