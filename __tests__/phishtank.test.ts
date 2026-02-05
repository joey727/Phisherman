import { PhishTankChecker } from "../src/checkers/phishtank";
import redis from "../src/utils/redis";

jest.mock("../src/utils/redis", () => ({
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
    sadd: jest.fn(),
    exists: jest.fn(),
    sismember: jest.fn(),
}));

describe("PhishTank Checker", () => {
    const mockedRedis = (redis as unknown) as jest.Mocked<any>;

    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe("PhishTankChecker.check", () => {
        it("should return score 100 for exact URL match", async () => {
            mockedRedis.sismember.mockResolvedValue(1);
            const result = await PhishTankChecker.check("http://malicious.com");
            expect(result.score).toBe(100);
            expect(result.reason).toContain("Exact URL match");
        });

        it("should return score 0 for no match", async () => {
            mockedRedis.sismember.mockResolvedValue(0);
            const result = await PhishTankChecker.check("http://safe.com");
            expect(result.score).toBe(0);
        });

        it("should handle redis errors gracefully", async () => {
            mockedRedis.sismember.mockRejectedValue(new Error("Redis down"));
            const result = await PhishTankChecker.check("http://safe.com");
            expect(result.score).toBe(0);
        });
    });
});
