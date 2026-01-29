import { URLHausChecker, loadURLHaus } from "../src/checkers/urlHaus";
import redis from "../src/utils/redis";
import axios from "axios";
import { Readable } from "stream";

jest.mock("../src/utils/redis", () => ({
  __esModule: true,
  default: {
    get: jest.fn(),
    set: jest.fn(),
    sismember: jest.fn(),
    exists: jest.fn(),
    del: jest.fn(),
    sadd: jest.fn(),
    rename: jest.fn(),
  },
}));

jest.mock("axios");
const mockedAxios = axios as jest.Mocked<typeof axios>;
const mockedRedis = redis as jest.Mocked<typeof redis>;

describe("URLHaus checker", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("checkURLHaus", () => {
    test("detects phishing URL", async () => {
      mockedRedis.sismember.mockResolvedValue(1); // 1 = true in Redis response

      const result = await URLHausChecker.check(
        "http://malicious.com/phish"
      );

      expect(result.score).toBe(100);
      expect(result.reason).toMatch(/URLHaus/i);
    });

    test("returns safe for clean URL", async () => {
      mockedRedis.sismember.mockResolvedValue(0);

      const result = await URLHausChecker.check("https://google.com");

      expect(result.score).toBe(0);
    });
  });

  describe("loadURLHaus", () => {
    test("should fetch stream and populate redis", async () => {
      mockedRedis.get.mockResolvedValue(null); // Cache expired

      const csvData = [
        "# Comment",
        '"1","2023-01-01","http://bad.com/malware","online","malware","tags","link","reporter"',
        '"2","2023-01-01","http://evil.com/exe","online","malware","tags","link","reporter"'
      ].join("\n");

      const stream = Readable.from([csvData]);
      mockedAxios.get.mockResolvedValue({
        data: stream,
        headers: {},
        status: 200
      });

      await loadURLHaus();

      expect(mockedAxios.get).toHaveBeenCalledWith(expect.stringContaining("csv-online"), expect.objectContaining({ responseType: "stream" }));

      expect(mockedRedis.sadd).toHaveBeenCalledWith(expect.stringContaining("_temp"), "http://bad.com/malware", "http://evil.com/exe");
      expect(mockedRedis.rename).toHaveBeenCalled();
    });
  });
});

