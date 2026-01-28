import { URLHausChecker } from "../src/checkers/urlHaus";
import redis from "../src/utils/redis";

jest.mock("../src/utils/redis", () => ({
  __esModule: true,
  default: {
    get: jest.fn(),
    set: jest.fn(),
    sismember: jest.fn(),
    exists: jest.fn(),
  },
}));

describe("URLHaus checker", () => {
  const mockedRedis = redis as jest.Mocked<typeof redis>;

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

