import axios from "axios";
import { checkPhishTank, loadPhishTank } from "../src/checkers/phishtank";
import redis from "../src/utils/redis";

// Mock axios and redis
jest.mock("axios");
jest.mock("../src/utils/redis", () => {
    const store = new Map<string, any>();
    const sets = new Map<string, Set<string>>();

    return {
        get: jest.fn(async (key: string) => store.get(key)),
        set: jest.fn(async (key: string, value: any) => store.set(key, value)),
        del: jest.fn(async (...keys: string[]) => {
            keys.forEach(k => {
                store.delete(k);
                sets.delete(k);
            });
        }),
        sadd: jest.fn(async (key: string, ...values: string[]) => {
            if (!sets.has(key)) sets.set(key, new Set());
            values.forEach(v => sets.get(key)!.add(v));
        }),
        sismember: jest.fn(async (key: string, value: string) => {
            return (sets.get(key)?.has(value) || sets.get("phishtank_urls")?.has(value)) ? 1 : 0;
        }),
        rename: jest.fn(async (oldKey: string, newKey: string) => {
            if (store.has(oldKey)) {
                store.set(newKey, store.get(oldKey));
                store.delete(oldKey);
            }
            if (sets.has(oldKey)) {
                sets.set(newKey, sets.get(oldKey)!);
                sets.delete(oldKey);
            }
        }),
        exists: jest.fn(async (key: string) => (sets.has(key) || store.has(key)) ? 1 : 0),
    };
});

describe("PhishTank Resilient Fetching", () => {
    const mockedAxios = axios as jest.Mocked<typeof axios>;

    beforeEach(async () => {
        jest.clearAllMocks();
        await redis.del("phishtank_urls", "phishtank_last_update");
    });

    test("should flag malicious URL from JSON feed", async () => {
        const mockData = [{ "url": "http://malicious-json.com/phish" }];
        const jsonString = JSON.stringify(mockData);
        const { Readable } = require('stream');
        const stream = new Readable();
        stream.push(jsonString);
        stream.push(null);

        mockedAxios.get.mockResolvedValueOnce({
            status: 200,
            data: stream as any,
            headers: { "content-type": "application/json" }
        });

        await loadPhishTank();

        const result = await checkPhishTank("http://malicious-json.com/phish");
        expect(result.score).toBe(100);
    });

    test("should NOT flag the root domain of a safe host", async () => {
        const mockData = [{ "url": "http://safe-host.com/login-phishing" }];
        const jsonString = JSON.stringify(mockData);
        const { Readable } = require('stream');
        const stream = new Readable();
        stream.push(jsonString);
        stream.push(null);

        mockedAxios.get.mockResolvedValueOnce({
            status: 200,
            data: stream as any,
            headers: { "content-type": "application/json" }
        });

        await loadPhishTank();

        const resultSafe = await checkPhishTank("http://safe-host.com/");
        expect(resultSafe.score).toBe(0);
    });
});
