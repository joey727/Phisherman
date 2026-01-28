import axios from "axios";
import { loadPhishTank, PhishTankChecker } from "../src/checkers/phishtank";
import redis from "../src/utils/redis";

jest.mock("axios");
jest.mock("../src/utils/redis", () => ({
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
    sadd: jest.fn(),
    exists: jest.fn(),
    sismember: jest.fn(),
}));

describe("PhishTank Checker Regression Test", () => {
    const mockedAxios = axios as jest.Mocked<typeof axios>;
    const mockedRedis = (redis as unknown) as jest.Mocked<any>;

    beforeEach(() => {
        jest.clearAllMocks();
        // Reset env var before each test
        delete process.env.PHISHTANK_API_URL;
    });

    it("should append format=json to the URL if missing", async () => {
        process.env.PHISHTANK_API_URL = "http://data.phishtank.com/data/online-valid.json";
        mockedRedis.get.mockResolvedValue(null); // Force refresh

        // Mock successful empty JSON response to avoid crash
        mockedAxios.get.mockResolvedValue({
            status: 200,
            data: Buffer.from(JSON.stringify([])),
        });

        await loadPhishTank();

        expect(mockedAxios.get).toHaveBeenCalledWith(
            expect.stringContaining("format=json"),
            expect.any(Object)
        );
    });

    it("should NOT append format=json if already present", async () => {
        process.env.PHISHTANK_API_URL = "http://data.phishtank.com/data/online-valid.json?format=json&foo=bar";
        mockedRedis.get.mockResolvedValue(null); // Force refresh

        mockedAxios.get.mockResolvedValue({
            status: 200,
            data: Buffer.from(JSON.stringify([])),
        });

        await loadPhishTank();

        expect(mockedAxios.get).toHaveBeenCalledWith(
            "http://data.phishtank.com/data/online-valid.json?format=json&foo=bar",
            expect.any(Object)
        );
    });

    it("should gracefully handle invalid JSON (XML) response and throw informative error", async () => {
        process.env.PHISHTANK_API_URL = "http://data.phishtank.com/data/online-valid.json";
        mockedRedis.get.mockResolvedValue(null); // Force refresh

        // Mock XML response
        const xmlResponse = "<?xml version='1.0'?><error>Invalid key</error>";
        mockedAxios.get.mockResolvedValue({
            status: 200,
            data: Buffer.from(xmlResponse),
        });

        const consoleSpy = jest.spyOn(console, "error").mockImplementation(() => { });

        await loadPhishTank();

        expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("Failed to parse PhishTank response as JSON."));
        expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining("First 200 chars of response"));

        consoleSpy.mockRestore();
    });

    it("should process valid PhishTank data and populate Redis", async () => {
        process.env.PHISHTANK_API_URL = "http://data.phishtank.com/data/online-valid.json";
        mockedRedis.get.mockResolvedValue(null); // Force refresh

        const mockData = [
            { url: "http://example.com/phish1", phishing_id: 123 },
            { url: "http://malicious.net/login", phishing_id: 124 }
        ];

        mockedAxios.get.mockResolvedValue({
            status: 200,
            data: Buffer.from(JSON.stringify(mockData)),
        });

        await loadPhishTank();

        // Check if logs are fired (implicit via inspection, or spy if needed)
        // Check Redis calls
        expect(mockedRedis.del).toHaveBeenCalled(); // Should clear old keys
        expect(mockedRedis.sadd).toHaveBeenCalled(); // Should add new URLs/Hosts
        expect(mockedRedis.set).toHaveBeenCalledWith(expect.stringContaining("phishtank_last_update"), expect.any(String));
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
