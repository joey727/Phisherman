import { analyzeUrl } from "../src/Scanner";

jest.mock("../src/checkers/openphish", () => ({
  checkOpenPhish: async () => ({ score: 100, reason: "OpenPhish hit" }),
}));

jest.mock("../src/checkers/urlHaus", () => ({
  checkURLHaus: async () => ({ score: 0 }),
}));

jest.mock("../src/checkers/heuristics", () => ({
  runHeuristics: () => ({
    score: 30,
    reasons: ["Suspicious keywords"],
  }),
}));

describe("Scanner aggregation", () => {
  test("returns phishing verdict for high score", async () => {
    const result = await analyzeUrl("http://bad-site.com");

    expect(result.verdict).toBe("danger");
    expect(result.score).toBeGreaterThanOrEqual(80);
  });
});
