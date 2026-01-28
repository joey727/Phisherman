// describe("Heuristics checks", () => {
//   test("flags IP-based URL as phishing", async () => {
//     const result = await heuristicCheck("http://103.179.57.164/login.php");

//     expect(result.score).toBeGreaterThanOrEqual(50);
//     expect(result.reason).toContain("IP-based URL");
//   });

//   test("flags suspicious TLD", async () => {
//     const result = await heuristicCheck("https://paypal.verify-login.tk");

//     expect(result.score).toBeGreaterThan(0);
//     expect(result.reason).toMatch(/tld/i);
//   });

//   test("detects brand impersonation", async () => {
//     const result = await heuristicCheck(
//       "https://secure-paypal-login.example.com"
//     );

//     expect(result.reason).toMatch(/paypal/i);
//   });

//   test("does not penalize normal site", async () => {
//     const result = await heuristicCheck("https://github.com");

//     expect(result.score).toBe(0);
//   });
// });

import { HeuristicsChecker } from "../src/checkers/heuristics";

jest.mock("../src/utils/redis", () => ({
  __esModule: true,
  default: {
    get: jest.fn(),
    set: jest.fn(),
    expire: jest.fn(),
  },
}));

jest.mock("whois-json", () => {
  return jest.fn(async () => ({
    createdDate: "2025-01-01",
    registrar: "Fake Registrar",
  }));
});

describe("Heuristics checker", () => {
  test("returns score for suspicious URL", async () => {
    const result = await HeuristicsChecker.check("http://login-secure-paypal.com");
    expect(result.score).toBeGreaterThan(0);
    expect(result.reasons?.length).toBeGreaterThan(0);
  });

  test("returns high score for non-HTTPS URL", async () => {
    const result = await HeuristicsChecker.check("http://example.com");
    expect(result.reasons).toContain("URL is not HTTPS");
  });
});

