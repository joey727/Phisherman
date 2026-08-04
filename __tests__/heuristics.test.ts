import { HeuristicsChecker } from "../src/checkers/heuristics";

jest.mock("../src/utils/redis", () => {
  const store = new Map<string, any>();
  return {
    get: jest.fn(async (key: string) => store.get(key)),
    set: jest.fn(async (key: string, value: any) => store.set(key, value)),
    hget: jest.fn(async (key: string, field: string) => {
      const h = store.get(key) || {};
      return h[field];
    }),
    hset: jest.fn(async (key: string, data: any) => {
      const h = store.get(key) || {};
      Object.assign(h, data);
      store.set(key, h);
    }),
    zadd: jest.fn(async () => {}),
    zrange: jest.fn(async () => []),
    hdel: jest.fn(async () => {}),
    zrem: jest.fn(async () => {}),
    pipeline: jest.fn(() => ({
      hset: jest.fn().mockReturnThis(),
      zadd: jest.fn().mockReturnThis(),
      hdel: jest.fn().mockReturnThis(),
      zrem: jest.fn().mockReturnThis(),
      exec: jest.fn(async () => [1, 1]),
    })),
  };
});

jest.mock("../src/utils/network", () => ({
  safeResolveHost: jest.fn(async () => ["1.2.3.4"]),
  blockIfPrivate: jest.fn(),
}));

jest.mock("whois-json", () => {
  return jest.fn(async () => ({
    createdDate: "2025-01-01",
    registrar: "Fake Registrar",
  }));
});

describe("Heuristics checker", () => {
  test("returns score for suspicious URL", async () => {
    const result = await HeuristicsChecker.check(
      "http://login-secure-paypal.com",
    );
    expect(result.score).toBeGreaterThan(0);
    expect(result.reasons?.length).toBeGreaterThan(0);
  });

  test("returns high score for non-HTTPS URL", async () => {
    const result = await HeuristicsChecker.check("http://example.com");
    expect(result.reasons).toContain("URL is not HTTPS");
  });
});
