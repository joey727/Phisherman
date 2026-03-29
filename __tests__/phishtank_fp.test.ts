import axios from "axios";
import { checkPhishTank, loadPhishTank } from "../src/checkers/phishtank";
import redis from "../src/utils/redis";

// Mock axios and redis
jest.mock("axios");
jest.mock("zlib", () => {
    const actualZlib = jest.requireActual("zlib");
    return {
        ...actualZlib,
        createGunzip: jest.fn(() => {
            const { PassThrough } = require("stream");
            return new PassThrough();
        }),
    };
});

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
        pipeline: jest.fn(() => ({
            hdel: jest.fn().mockReturnThis(),
            zrem: jest.fn().mockReturnThis(),
            exec: jest.fn().mockResolvedValue([1, 1]),
        })),
    };
});

describe("PhishTank Resilient Fetching", () => {
    const mockedAxios = axios as jest.Mocked<typeof axios>;

    beforeEach(async () => {
        jest.clearAllMocks();
        await redis.del("phishtank_urls", "phishtank_last_update");
    });

    test("should flag malicious URL from CSV feed", async () => {
        const mockCsv = 'id,url,phish_id,phish_detail_url,submission_time,verified,verification_time,online,target\n' +
                        '"123","http://malicious-csv.com/phish","456","http://phishtank.com/456","2024-01-01","yes","2024-01-01","yes","Other"';
        const { Readable } = require('stream');
        const stream = new Readable();
        stream.push(mockCsv);
        stream.push(null);

        mockedAxios.get.mockResolvedValueOnce({
            status: 200,
            data: stream as any,
            headers: { "content-type": "text/csv" }
        } as any);

        await loadPhishTank();

        const result = await checkPhishTank("http://malicious-csv.com/phish");
        expect(result.score).toBe(100);
    });

    test("should NOT flag the root domain of a safe host", async () => {
        const mockCsv = 'id,url,phish_id\n"123","http://safe-host.com/login-phishing","456"';
        const { Readable } = require('stream');
        const stream = new Readable();
        stream.push(mockCsv);
        stream.push(null);

        mockedAxios.get.mockResolvedValueOnce({
            status: 200,
            data: stream as any,
            headers: { "content-type": "text/csv" }
        } as any);

        await loadPhishTank();

        const resultSafe = await checkPhishTank("http://safe-host.com/");
        expect(resultSafe.score).toBe(0);
    });
});
