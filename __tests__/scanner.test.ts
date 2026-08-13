jest.mock("../src/utils/redis", () => {
  const hsetCalls: { key: string; data: Record<string, string> }[] = [];
  const mock = {
    get: jest.fn(),
    set: jest.fn(),
    hget: jest.fn().mockResolvedValue(null),
    hset: jest.fn((key: string, data: Record<string, string>) => {
      hsetCalls.push({ key, data });
      return Promise.resolve(1);
    }),
    zadd: jest.fn(),
    del: jest.fn(),
    sadd: jest.fn(),
    rename: jest.fn(),
    pipeline: jest.fn(() => ({
      hset: jest.fn().mockReturnThis(),
      zadd: jest.fn().mockReturnThis(),
      hdel: jest.fn().mockReturnThis(),
      zrem: jest.fn().mockReturnThis(),
      exec: jest.fn().mockResolvedValue([1, 1]),
    })),
  };
  mock.__hsetCalls = hsetCalls;
  return mock;
});

jest.mock("../src/checkers/heuristics", () => ({ HeuristicsChecker: { name: "heuristics", check: jest.fn() } }));
jest.mock("../src/checkers/openPhish", () => ({ OpenPhishChecker: { name: "openphish", check: jest.fn() } }));
jest.mock("../src/checkers/googleSafeBrowsing", () => ({ SafeBrowsingChecker: { name: "google_safe_browsing", check: jest.fn() } }));
jest.mock("../src/checkers/urlHaus", () => ({ URLHausChecker: { name: "urlhaus", check: jest.fn() } }));
jest.mock("../src/checkers/phishtank", () => ({ PhishTankChecker: { name: "phishtank", check: jest.fn() } }));
jest.mock("../src/checkers/googleWebRisk", () => ({ WebRiskChecker: { name: "google_web_risk", check: jest.fn() } }));

jest.mock("../src/CheckerRegistry", () => ({
  registry: {
    register: jest.fn(),
    runAll: jest.fn(async () => ({
      checks: [
        { score: 50, reasons: ["Found in blacklist"] },
        { score: 30, reason: "Suspicious pattern" }
      ],
      timing: {
        "checker1": 10,
        "checker2": 20
      }
    })),
  },
}));

import { analyzeUrl } from "../src/Scanner";
import { registry } from "../src/CheckerRegistry";
import redis from "../src/utils/redis";

describe("Scanner aggregation", () => {
  test("returns correct verdict and aggregated data", async () => {
    const result = await analyzeUrl("http://bad-site.com");

    expect(result.verdict).toBe("phishing");
    expect(result.score).toBe(80);
    expect(result.reasons).toContain("Found in blacklist");
    expect(result.reasons).toContain("Suspicious pattern");
    expect(result.executionTimeMs).toBeDefined();
    expect(result.executionTimeMs?.checker1).toBe(10);
  });

  test("clamps total score at 100", async () => {
    (registry.runAll as jest.Mock).mockResolvedValueOnce({
      checks: [
        { score: 70 },
        { score: 40 }
      ],
      timing: {}
    });

    const result = await analyzeUrl("http://bad-site.com");
    expect(result.score).toBe(100);
    expect(result.verdict).toBe("phishing");
  });

  test("defaults to free tier and returns tier in the result", async () => {
    const result = await analyzeUrl("http://bad-site.com");

    expect(result.tier).toBe("free");
    expect(registry.runAll).toHaveBeenCalledWith(
      "http://bad-site.com",
      expect.anything(),
      { tier: "free" },
    );
  });

  test("passes an explicit tier into the registry and result", async () => {
    const result = await analyzeUrl("http://bad-site.com", { tier: "pro" });

    expect(result.tier).toBe("pro");
    expect(registry.runAll).toHaveBeenCalledWith(
      "http://bad-site.com",
      expect.anything(),
      { tier: "pro" },
    );
  });

  test("uses tier-scoped cache keys so free/pro results never mix", async () => {
    const mockedHsetCalls = (redis as unknown as { __hsetCalls: { key: string; data: Record<string, string> }[] }).__hsetCalls;
    mockedHsetCalls.length = 0;

    await analyzeUrl("http://mix-test.com", { tier: "free" });
    await analyzeUrl("http://mix-test.com", { tier: "pro" });

    expect(mockedHsetCalls.length).toBe(2);
    const freeField = Object.keys(mockedHsetCalls[0].data)[0];
    const proField = Object.keys(mockedHsetCalls[1].data)[0];
    expect(freeField).not.toBe(proField);
  });

  test("drops ML contribution when an established-domain veto fires", async () => {
    (registry.runAll as jest.Mock).mockResolvedValueOnce({
      checks: [
        { name: "heuristics", score: 0, veto: true, reasons: [] },
        { name: "ml", score: 60 },
        { name: "urlhaus", score: 0 },
      ],
      timing: {},
    });

    const result = await analyzeUrl("https://www.miele.com/");
    expect(result.score).toBe(0);
    expect(result.verdict).toBe("safe");
    expect(result.reasons).toContain(
      "Established domain with clean URL (reputation veto)",
    );
  });

  test("keeps ML score when no veto fires", async () => {
    (registry.runAll as jest.Mock).mockResolvedValueOnce({
      checks: [
        { name: "heuristics", score: 0 },
        { name: "ml", score: 60 },
      ],
      timing: {},
    });

    const result = await analyzeUrl("https://example.com/");
    expect(result.score).toBe(60);
    expect(result.verdict).toBe("suspicious");
  });

  test("keeps feed scores even when a veto fires (compromised old domain)", async () => {
    (registry.runAll as jest.Mock).mockResolvedValueOnce({
      checks: [
        { name: "heuristics", score: 0, veto: true, reasons: [] },
        { name: "ml", score: 60 },
        { name: "urlhaus", score: 80, reasons: ["Found in blacklist"] },
      ],
      timing: {},
    });

    const result = await analyzeUrl("https://www.miele.com/");
    expect(result.score).toBe(80);
    expect(result.verdict).toBe("phishing");
  });
});


