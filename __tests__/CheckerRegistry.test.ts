import { registry } from "../src/CheckerRegistry";
import { Checker } from "../src/types";

describe("CheckerRegistry", () => {
    beforeEach(() => {
        // Clear registry before each test
        (registry as any).checkers = [];
    });

    test("registers a checker", () => {
        const mockChecker: Checker = {
            name: "mock",
            check: jest.fn(),
        };
        registry.register(mockChecker);
        expect(registry.getCheckers()).toContain(mockChecker);
    });

    test("runs all checkers and returns timing", async () => {
        const checker1: Checker = {
            name: "c1",
            check: jest.fn().mockResolvedValue({ score: 10 }),
        };
        const checker2: Checker = {
            name: "c2",
            check: jest.fn().mockResolvedValue({ score: 20 }),
        };

        registry.register(checker1);
        registry.register(checker2);

        const { checks, timing } = await registry.runAll("test.com");

        expect(checks).toHaveLength(2);
        expect(checks[0].score).toBe(10);
        expect(checks[1].score).toBe(20);
        expect(timing.c1).toBeDefined();
        expect(timing.c2).toBeDefined();
    });

    test("handles checker failures gracefully", async () => {
        const checker1: Checker = {
            name: "fail",
            check: jest.fn().mockRejectedValue(new Error("Failed")),
        };
        registry.register(checker1);

        const { checks } = await registry.runAll("test.com");
        expect(checks[0].score).toBe(0);
        expect(checks[0].reason).toContain("Checker fail error");
    });
});
