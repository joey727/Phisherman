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
            return sets.get(key)?.has(value) ? 1 : 0;
        }),
        exists: jest.fn(async (key: string) => sets.has(key) || store.has(key) ? 1 : 0),
        default: {
            get: async (key: string) => store.get(key),
            set: async (key: string, value: any) => store.set(key, value),
            del: async (...keys: string[]) => {
                keys.forEach(k => {
                    store.delete(k);
                    sets.delete(k);
                });
            },
            sadd: async (key: string, ...values: string[]) => {
                if (!sets.has(key)) sets.set(key, new Set());
                values.forEach(v => sets.get(key)!.add(v));
            },
            sismember: async (key: string, value: string) => {
                return sets.get(key)?.has(value) ? 1 : 0;
            },
            exists: async (key: string) => sets.has(key) || store.has(key) ? 1 : 0,
        }
    };
});

describe("PhishTank False Positive Reproduction", () => {
    const mockedAxios = axios as jest.Mocked<typeof axios>;

    beforeEach(async () => {
        jest.clearAllMocks();
        await redis.del("phishtank_urls", "phishtank_hosts", "phishtank_last_update");
    });

    test("should flag specific malicious URL on a safe host", async () => {
        const mockData = [
            {
                "url": "http://safe-host.com/login-phishing",
                "phish_id": "123456",
                "online": "yes"
            }
        ];

        const jsonString = JSON.stringify(mockData);
        mockedAxios.get.mockResolvedValueOnce({
            status: 200,
            data: Buffer.from(jsonString)
        });

        await loadPhishTank();

        const resultBad = (await checkPhishTank("http://safe-host.com/login-phishing"))!;
        expect(resultBad.score).toBe(100);
    });

    test("should NOT flag the root domain of a safe host", async () => {
        const mockData = [
            {
                "url": "http://safe-host.com/login-phishing",
                "phish_id": "123456",
                "online": "yes"
            }
        ];

        const jsonString = JSON.stringify(mockData);
        mockedAxios.get.mockResolvedValueOnce({
            status: 200,
            data: Buffer.from(jsonString)
        });

        await loadPhishTank();

        // The root domain is safe, it should not be flagged just because a sub-resource is malicious
        const resultSafe = (await checkPhishTank("http://safe-host.com/"))!;

        expect(resultSafe.score).toBe(0);
    });
});
