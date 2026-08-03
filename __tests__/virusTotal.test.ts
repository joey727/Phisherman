import { checkVirusTotal } from "../src/checkers/virusTotal";
import { HashCache } from "../src/utils/hashCache";
import axios from "axios";

jest.mock("axios");
const mockedAxios = axios as jest.Mocked<typeof axios>;

jest.mock("../src/utils/hashCache", () => {
    return {
        HashCache: jest.fn().mockImplementation(() => {
            return {
                get: jest.fn().mockResolvedValue(null),
                set: jest.fn().mockResolvedValue(undefined),
                delete: jest.fn().mockResolvedValue(undefined),
                cleanup: jest.fn().mockResolvedValue(0)
            };
        })
    };
});

describe("VirusTotalChecker", () => {
    const originalEnv = process.env;

    beforeEach(() => {
        process.env = { ...originalEnv, VIRUSTOTAL_API_KEY: "test_key", VT_RATE_LIMIT: "4" };
        jest.clearAllMocks();
    });

    afterEach(() => {
        process.env = originalEnv;
    });

    test("skips silently when no API key is set", async () => {
        delete process.env.VIRUSTOTAL_API_KEY;
        const result = await checkVirusTotal("http://example.com");
        expect(result).toEqual({ score: 0 });
        expect(mockedAxios.get).not.toHaveBeenCalled();
    });

    test("returns score based on malicious and suspicious counts", async () => {
        mockedAxios.get.mockResolvedValueOnce({
            data: {
                data: {
                    attributes: {
                        last_analysis_stats: {
                            malicious: 3,
                            suspicious: 1,
                            harmless: 80
                        },
                        categories: {
                            "Fortinet": "malware"
                        }
                    }
                }
            }
        });

        const result = await checkVirusTotal("http://malware.com");
        
        expect(result.score).toBe(35); // 3*10 + 1*5
        expect(result.reasons).toContainEqual(expect.stringContaining("malicious"));
        expect(result.reasons).toContainEqual(expect.stringContaining("suspicious"));
        expect(result.reasons).toContainEqual(expect.stringContaining("category: malware"));
    });

    test("caps score at 100", async () => {
        mockedAxios.get.mockResolvedValueOnce({
            data: {
                data: {
                    attributes: {
                        last_analysis_stats: {
                            malicious: 15,
                            suspicious: 0,
                            harmless: 0
                        }
                    }
                }
            }
        });

        const result = await checkVirusTotal("http://bad2.com");
        expect(result.score).toBe(100); 
    });

    test("returns 0 score for safe URLs", async () => {
        mockedAxios.get.mockResolvedValueOnce({
            data: {
                data: {
                    attributes: {
                        last_analysis_stats: {
                            malicious: 0,
                            suspicious: 0,
                            harmless: 90
                        }
                    }
                }
            }
        });

        const result = await checkVirusTotal("http://google.com");
        expect(result.score).toBe(0);
        expect(result.reasons).toBeUndefined();
    });

    test("handles API errors gracefully", async () => {
        mockedAxios.get.mockRejectedValueOnce({
            response: { status: 404 }
        });

        const result = await checkVirusTotal("http://unknown.com");
        expect(result.score).toBe(0);
    });

});
