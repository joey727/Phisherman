import { cacheManager } from "../src/CacheManager";
import redis from "../src/utils/redis";

jest.mock("../src/utils/redis", () => ({
    zrange: jest.fn().mockResolvedValue([]),
    hdel: jest.fn().mockResolvedValue(1),
    zrem: jest.fn().mockResolvedValue(1),
    pipeline: jest.fn(() => ({
        hdel: jest.fn().mockReturnThis(),
        zrem: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([1, 1]),
    })),
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
}));

// Helper to flush all microtasks (promises)
const flush = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };

describe("CacheManager", () => {
    beforeEach(() => {
        cacheManager.stop();
        (cacheManager as any).tasks.clear();
        (cacheManager as any).isRunning = false;
        jest.useFakeTimers();
        jest.clearAllMocks();
    });

    afterEach(() => {
        jest.useRealTimers();
    });

    test("runs registered tasks", async () => {
        const mockTask = jest.fn().mockResolvedValue(undefined);
        cacheManager.addTask("test", mockTask);

        await cacheManager.runAll();
        expect(mockTask).toHaveBeenCalledTimes(1);
    });

    test("handles task failures without stopping other tasks", async () => {
        const failTask = jest.fn().mockRejectedValue(new Error("Fail"));
        const successTask = jest.fn().mockResolvedValue(undefined);

        cacheManager.addTask("fail", failTask);
        cacheManager.addTask("success", successTask);

        await cacheManager.runAll();
        expect(failTask).toHaveBeenCalled();
        expect(successTask).toHaveBeenCalled();
    });

    test("runs tasks on interval after start", async () => {
        const mockTask = jest.fn().mockResolvedValue(undefined);
        cacheManager.addTask("periodic", mockTask);

        // Start with short interval
        await cacheManager.start(1000);
        await flush();
        expect(mockTask).toHaveBeenCalledTimes(1); // Immediate run

        // Advance timer and wait for async runAll() to finish and schedule next
        jest.advanceTimersByTime(1100);
        await flush();
        expect(mockTask).toHaveBeenCalledTimes(2);

        jest.advanceTimersByTime(1100);
        await flush();
        expect(mockTask).toHaveBeenCalledTimes(3);
    });
});




