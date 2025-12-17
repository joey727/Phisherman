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

import { heuristicCheck } from "../src/checkers/heuristics";

jest.mock("whois-json", () => {
  return jest.fn(async () => ({
    createdDate: "2025-01-01",
    registrar: "Fake Registrar",
  }));
});

describe("Heuristics checker", () => {
  test("returns score for suspicious URL", async () => {
    const result = await heuristicCheck("http://login-secure-paypal.com");
    expect(result.score).toBeGreaterThan(0);
  });
});
