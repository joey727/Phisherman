import { OpenPhishChecker } from "../src/checkers/openPhish";
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

describe("OpenPhish checker", () => {
  const mockedRedis = redis as jest.Mocked<typeof redis>;

  test("detects malicious URL", async () => {
    mockedRedis.sismember.mockResolvedValue(1);
    const result = await OpenPhishChecker.check("http://bad-site.com/login");
    expect(result.score).toBe(100);
    expect(result.reason).toContain("OpenPhish");
  });

  test("returns safe for clean URL", async () => {
    mockedRedis.sismember.mockResolvedValue(0);
    const result = await OpenPhishChecker.check("https://github.com");
    expect(result.score).toBe(0);
  });
});

