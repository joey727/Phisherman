import * as urlhaus from "../src/checkers/urlHaus";

jest.spyOn(urlhaus as any, "loadURLHaus").mockResolvedValue([
  {
    url: "http://103.179.57.164/login.php",
    threat: "phishing",
  },
]);

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
