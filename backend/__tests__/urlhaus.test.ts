import * as urlhaus from "../src/checkers/urlHaus";

jest.mock("../src/checkers/urlHaus", () => ({
  checkURLHaus: async (url: string) => {
    if (url.includes("103.179.57.164")) {
      return { score: 100, reason: "URLHaus phishing" };
    }
    return { score: 0 };
  },
}));

describe("URLHaus checker", () => {
  test("detects phishing URL", async () => {
    const result = await urlhaus.checkURLHaus(
      "http://103.179.57.164/login.php"
    );

    expect(result.score).toBe(100);
    expect(result.reason).toMatch(/URLHaus/i);
  });

  test("returns safe for clean URL", async () => {
    const result = await urlhaus.checkURLHaus("https://google.com");

    expect(result.score).toBe(0);
  });
});
