import axios from "axios";
import { checkSafeBrowsing } from "../src/checkers/googleSafeBrowsing";

jest.mock("axios");
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe("checkSafeBrowsing", () => {
    const apiKey = process.env.GOOGLE_SAFE_API_KEY;

    beforeAll(() => {
        process.env.GOOGLE_SAFE_API_KEY = "test-api-key";
    });

    afterAll(() => {
        process.env.GOOGLE_SAFE_API_KEY = apiKey;
    });

    test("returns score 50 when matches are found", async () => {
        mockedAxios.post.mockResolvedValueOnce({
            data: {
                matches: [{ threatType: "MALWARE" }]
            }
        });

        const result = await checkSafeBrowsing("http://malicious.com");
        expect(result.score).toBe(50);
        expect(result.reason).toBeDefined();
    });

    test("returns score 0 when matches is an empty array (THE BUG)", async () => {
        mockedAxios.post.mockResolvedValueOnce({
            data: {
                matches: []
            }
        });

        const result = await checkSafeBrowsing("http://safe.com");
        // This is currently expected to fail (return 50) because of the truthy check on []
        expect(result.score).toBe(0);
    });

    test("returns score 0 when response is empty", async () => {
        mockedAxios.post.mockResolvedValueOnce({
            data: {}
        });

        const result = await checkSafeBrowsing("http://safe.com");
        expect(result.score).toBe(0);
    });
});
