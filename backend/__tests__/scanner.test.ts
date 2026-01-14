import { analyzeUrl } from "../src/Scanner";

jest.mock("../src/checkers/heuristics", () => ({
  heuristicCheck: jest.fn(async () => ({
    score: 80,
    verdict: "suspicious",
    reasons: ["Suspicious domain"],
    details: {},
  })),
}));

jest.mock("../src/checkers/googleSafeBrowsing", () => ({
  checkSafeBrowsing: jest.fn(async () => ({
    score: 20,
    verdict: "phishing",
    reasons: ["Google Safe Browsing hit"],
    details: {},
  })),
}));

jest.mock("../src/checkers/phishtank", () => ({
  checkPhishTank: jest.fn(async () => ({
    score: 0,
    verdict: "safe",
    reasons: [],
    details: {},
  })),
}));

jest.mock("../src/checkers/urlHaus", () => ({
  checkURLHaus: jest.fn(async () => ({
    score: 0,
    verdict: "safe",
    reasons: [],
    details: {},
  })),
}));

jest.mock("../src/checkers/googleWebRisk", () => ({
  checkGoogleWebRisk: jest.fn(async () => ({
    score: 0,
    verdict: "safe",
    reasons: [],
    details: {},
  })),
}));

jest.mock("../src/checkers/openPhish", () => ({
  checkOpenPhish: jest.fn(async () => ({
    score: 0,
    verdict: "safe",
    reasons: [],
    details: {},
  })),
}));

describe("Scanner aggregation", () => {
  test("returns phishing verdict for high score", async () => {
    const result = await analyzeUrl("http://bad-site.com");

    expect(result.verdict).toBe("phishing");
    expect(result.score).toBeGreaterThanOrEqual(80);
  });
});
