import { heuristicCheck as heuristics } from "../src/checkers/heuristics";

describe("Heuristics checks", () => {
  test("flags IP-based URL as phishing", async () => {
    const result = await heuristics("http://103.179.57.164/login.php");

    expect(result.score).toBeGreaterThanOrEqual(50);
    expect(result.reason).toContain("IP-based URL");
  });

  test("flags suspicious TLD", async () => {
    const result = await heuristics("https://paypal.verify-login.tk");

    expect(result.score).toBeGreaterThan(0);
    expect(result.reason).toMatch(/tld/i);
  });

  test("detects brand impersonation", async () => {
    const result = await heuristics("https://secure-paypal-login.example.com");

    expect(result.reason).toMatch(/paypal/i);
  });

  test("does not penalize normal site", async () => {
    const result = await heuristics("https://github.com");

    expect(result.score).toBe(0);
  });
});
