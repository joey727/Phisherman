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

  beforeEach(() => jest.clearAllMocks());

  test("detects malicious URL via exact match", async () => {
    mockedRedis.sismember.mockImplementation((key) =>
      key === "openphish_urls" ? Promise.resolve(1) : Promise.resolve(0),
    );
    const result = await OpenPhishChecker.check("http://bad-site.com/login");
    expect(result.score).toBe(100);
    expect(result.reason).toContain("OpenPhish");
  });

  test("detects malicious URL via host match", async () => {
    mockedRedis.sismember.mockImplementation((key, val) => {
      if (key === "openphish_urls") return Promise.resolve(0);
      if (key === "openphish_hosts" && val === "bad-site.com") return Promise.resolve(1);
      return Promise.resolve(0);
    });
    const result = await OpenPhishChecker.check("http://bad-site.com/login");
    expect(result.score).toBe(80);
    expect(result.reason).toContain("Domain listed in OpenPhish");
  });

  test("suppresses host-level match for a trusted apex", async () => {
    mockedRedis.sismember.mockImplementation((key) => {
      if (key === "openphish_urls") return Promise.resolve(0);
      if (key === "openphish_hosts") return Promise.resolve(1);
      return Promise.resolve(0);
    });
    const result = await OpenPhishChecker.check("https://vercel.com/dashboard");
    expect(result.score).toBe(0);
  });

  test("still matches a subdomain of a trusted apex", async () => {
    mockedRedis.sismember.mockImplementation((key, val) => {
      if (key === "openphish_urls") return Promise.resolve(0);
      if (key === "openphish_hosts" && val === "evil-1234.render.com") return Promise.resolve(1);
      return Promise.resolve(0);
    });
    const result = await OpenPhishChecker.check("https://evil-1234.render.com/x");
    expect(result.score).toBe(80);
  });

  test("returns safe for clean URL", async () => {
    mockedRedis.sismember.mockResolvedValue(0);
    const result = await OpenPhishChecker.check("https://github.com");
    expect(result.score).toBe(0);
  });
});