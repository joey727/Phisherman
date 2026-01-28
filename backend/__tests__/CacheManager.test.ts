import { cacheManager } from "../src/CacheManager";

describe("CacheManager", () => {
    beforeEach(() => {
        // Stop and clear tasks before each test
        cacheManager.stop();
        (cacheManager as any).tasks.clear();
        jest.useFakeTimers();
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
        expect(mockTask).toHaveBeenCalledTimes(1); // Immediate run

        jest.advanceTimersByTime(1001);
        expect(mockTask).toHaveBeenCalledTimes(2);

        jest.advanceTimersByTime(1001);
        expect(mockTask).toHaveBeenCalledTimes(3);
    });
});
