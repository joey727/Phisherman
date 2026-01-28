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
});


