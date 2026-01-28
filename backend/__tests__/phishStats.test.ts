import { loadPhishStats, checkPhishStats } from "../src/checkers/phishStats";
import redis from "../src/utils/redis";
import axios from "axios";

jest.mock("../src/utils/redis", () => ({
    get: jest.fn(),
    set: jest.fn(),
    del: jest.fn(),
    sadd: jest.fn(),
    sismember: jest.fn(),
    rename: jest.fn(),
}));

jest.mock("axios");
const mockedAxios = axios as jest.Mocked<typeof axios>;
const mockedRedis = redis as jest.Mocked<typeof redis>;

describe("PhishStats Checker", () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe("loadPhishStats", () => {
        it("should fetch data and populate redis when cache is expired", async () => {
            mockedRedis.get.mockResolvedValue(null); // Cache expired
            mockedAxios.get.mockResolvedValue({
                data: [
                    { id: 1, url: "http://malicious.com/login", ip: "1.2.3.4" },
                    { id: 2, url: "https://example.net/phishing", ip: "5.6.7.8" },
                ]
            });

            await loadPhishStats();

            expect(mockedAxios.get).toHaveBeenCalledTimes(1);
            // Verify atomic steps
            expect(mockedRedis.del).toHaveBeenCalledWith("phishstats_urls_temp");
            expect(mockedRedis.del).toHaveBeenCalledWith("phishstats_hosts_temp");

            // Verify insertion
            expect(mockedRedis.sadd).toHaveBeenCalledWith("phishstats_urls_temp", "http://malicious.com/login", "https://example.net/phishing");
            expect(mockedRedis.sadd).toHaveBeenCalledWith("phishstats_hosts_temp", "malicious.com", "example.net");

            // Verify rename
            expect(mockedRedis.rename).toHaveBeenCalledWith("phishstats_urls_temp", "phishstats_urls");
            expect(mockedRedis.rename).toHaveBeenCalledWith("phishstats_hosts_temp", "phishstats_hosts");
        });

        it("should skip refresh if cache is fresh", async () => {
            const now = Date.now();
            mockedRedis.get.mockResolvedValue(now.toString()); // Just updated

            await loadPhishStats();

            expect(mockedAxios.get).not.toHaveBeenCalled();
        });

        it("should handle API errors gracefully", async () => {
            mockedRedis.get.mockResolvedValue(null);
            mockedAxios.get.mockRejectedValue(new Error("API Down"));

            await loadPhishStats();

            // Should catch error and not crash
            expect(mockedRedis.rename).not.toHaveBeenCalled();
        });
    });

    describe("checkPhishStats", () => {
        it("should return match for exact URL", async () => {
            mockedRedis.sismember.mockImplementation((key, val) => {
                if (key === "phishstats_urls" && val === "http://bad.com") return Promise.resolve(1);
                return Promise.resolve(0);
            });

            const result = await checkPhishStats("http://bad.com");
            expect(result.score).toBe(100);
            expect(result.reason).toContain("Listed in PhishStats database");
        });

        it("should return match for hostname", async () => {
            mockedRedis.sismember.mockImplementation((key, val) => {
                if (key === "phishstats_urls") return Promise.resolve(0);
                if (key === "phishstats_hosts" && val === "bad.com") return Promise.resolve(1);
                return Promise.resolve(0);
            });

            const result = await checkPhishStats("http://bad.com/login");
            expect(result.score).toBe(80);
            expect(result.reason).toContain("Domain listed in PhishStats");
        });

        it("should return safe for unknown URL", async () => {
            mockedRedis.sismember.mockResolvedValue(0);

            const result = await checkPhishStats("http://google.com");
            expect(result.score).toBe(0);
        });
    });
});
