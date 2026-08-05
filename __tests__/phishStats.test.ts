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

const URL_PATTERN = /\/api\/phishing\?/;
const makeEntries = (ids: number[]) =>
    ids.map((id) => ({ id, url: `http://${id}.malicious.com/login`, ip: "1.2.3.4" }));

describe("PhishStats Checker", () => {
    let envBackup: { [k: string]: string | undefined };
    beforeEach(() => {
        jest.clearAllMocks();
        envBackup = {
            PHISHSTATS_API_KEY: process.env.PHISHSTATS_API_KEY,
            PHISHSTATS_MAX_PAGES: process.env.PHISHSTATS_MAX_PAGES,
        };
    });
    afterEach(() => {
        if (envBackup.PHISHSTATS_API_KEY === undefined) delete process.env.PHISHSTATS_API_KEY;
        else process.env.PHISHSTATS_API_KEY = envBackup.PHISHSTATS_API_KEY;
        if (envBackup.PHISHSTATS_MAX_PAGES === undefined) delete process.env.PHISHSTATS_MAX_PAGES;
        else process.env.PHISHSTATS_MAX_PAGES = envBackup.PHISHSTATS_MAX_PAGES;
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

            // One page because the response has fewer than 100 rows.
            expect(mockedAxios.get).toHaveBeenCalledTimes(1);
            expect(mockedAxios.get).toHaveBeenCalledWith(
                expect.stringMatching(URL_PATTERN),
                expect.objectContaining({ timeout: 45000 }),
            );
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

        it("should paginate until a page returns fewer than 100 rows", async () => {
            mockedRedis.get.mockResolvedValue(null);
            const ids = Array.from({ length: 100 }, (_, i) => 200 - i);
            mockedAxios.get
                .mockResolvedValueOnce({ data: makeEntries(ids) }) // full page 1
                .mockResolvedValueOnce({ data: makeEntries([99, 98]) }); // short page 2

            await loadPhishStats();

            expect(mockedAxios.get).toHaveBeenCalledTimes(2);
            expect(mockedAxios.get).toHaveBeenNthCalledWith(1,
                expect.stringContaining("_p=1"), expect.anything());
            expect(mockedAxios.get).toHaveBeenNthCalledWith(2,
                expect.stringContaining("_p=2"), expect.anything());
            // 102 entries -> single sadd batch on each temp key
            expect(mockedRedis.sadd).toHaveBeenCalledWith("phishstats_urls_temp", ...ids.map((i) => `http://${i}.malicious.com/login`), "http://99.malicious.com/login", "http://98.malicious.com/login");
            expect(mockedRedis.rename).toHaveBeenCalledWith("phishstats_urls_temp", "phishstats_urls");
        });

        it("should stop at the page budget when pages stay full (no API key)", async () => {
            mockedRedis.get.mockResolvedValue(null);
            delete process.env.PHISHSTATS_API_KEY;
            delete process.env.PHISHSTATS_MAX_PAGES;
            const ids = Array.from({ length: 100 }, (_, i) => 1000 - i);
            mockedAxios.get.mockResolvedValue({ data: makeEntries(ids) });

            await loadPhishStats();

            // No key -> max 3 pages per refresh to stay within anonymous quota.
            expect(mockedAxios.get).toHaveBeenCalledTimes(3);
        });

        it("should honor a larger page budget when an API key is set", async () => {
            mockedRedis.get.mockResolvedValue(null);
            process.env.PHISHSTATS_API_KEY = "psk_test";
            process.env.PHISHSTATS_MAX_PAGES = "5";
            const ids = Array.from({ length: 100 }, (_, i) => 1000 - i);
            mockedAxios.get.mockResolvedValue({ data: makeEntries(ids) });

            await loadPhishStats();

            expect(mockedAxios.get).toHaveBeenCalledTimes(5);
        });

        it("should send X-API-Key header when a key is configured", async () => {
            mockedRedis.get.mockResolvedValue(null);
            process.env.PHISHSTATS_API_KEY = "psk_secret";
            process.env.PHISHSTATS_MAX_PAGES = "1";
            mockedAxios.get.mockResolvedValue({ data: makeEntries([1, 2]) });

            await loadPhishStats();

            expect(mockedAxios.get).toHaveBeenCalledWith(
                expect.stringContaining("_p=1"),
                expect.objectContaining({ headers: expect.objectContaining({ "X-API-Key": "psk_secret" }) }),
            );
        });

        it("should keep the previous cache when the feed returns 0 entries", async () => {
            mockedRedis.get.mockResolvedValue(null);
            mockedAxios.get.mockResolvedValue({ data: [] });

            await loadPhishStats();

            expect(mockedRedis.rename).not.toHaveBeenCalled();
            expect(mockedRedis.set).not.toHaveBeenCalled();
        });

        it("should skip refresh if cache is fresh", async () => {
            const now = Date.now();
            mockedRedis.get.mockResolvedValue(now.toString()); // Just updated

            await loadPhishStats();

            expect(mockedAxios.get).not.toHaveBeenCalled();
        });

        it("should handle API errors gracefully (e.g. 429)", async () => {
            mockedRedis.get.mockResolvedValue(null);
            mockedAxios.get.mockRejectedValue(new Error("API Down"));

            await loadPhishStats();

            // Should catch error and not crash / not discard the previous cache
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

        it("should suppress host-level match for a trusted apex", async () => {
            // vercel.com is in the host set, but its apex is trusted -> safe.
            mockedRedis.sismember.mockImplementation((key) => {
                if (key === "phishstats_urls") return Promise.resolve(0);
                if (key === "phishstats_hosts") return Promise.resolve(1);
                return Promise.resolve(0);
            });

            const result = await checkPhishStats("https://vercel.com/dashboard");
            expect(result.score).toBe(0);
        });

        it("should still match a subdomain of a trusted apex", async () => {
            // Arbitrary user subdomain is NOT suppressed by the apex trust.
            mockedRedis.sismember.mockImplementation((key, val) => {
                if (key === "phishstats_urls") return Promise.resolve(0);
                if (key === "phishstats_hosts" && val === "evil-1234.render.com") return Promise.resolve(1);
                return Promise.resolve(0);
            });

            const result = await checkPhishStats("https://evil-1234.render.com/x");
            expect(result.score).toBe(80);
        });

        it("should still match exact URL on a trusted apex", async () => {
            mockedRedis.sismember.mockImplementation((key, val) => {
                if (key === "phishstats_urls" && val === "https://vercel.com/login?next=abc") return Promise.resolve(1);
                return Promise.resolve(0);
            });

            const result = await checkPhishStats("https://vercel.com/login?next=abc");
            expect(result.score).toBe(100);
        });

        it("should return safe for unknown URL", async () => {
            mockedRedis.sismember.mockResolvedValue(0);

            const result = await checkPhishStats("http://google.com");
            expect(result.score).toBe(0);
        });
    });
});
