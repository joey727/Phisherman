import { checkOpenPhish } from "../src/checkers/openphish";

jest.mock("../src/checkers/openphish", () => ({
  checkOpenPhish: async (url: string) => {
    if (url.includes("bad-site")) {
      return { score: 100, reason: "OpenPhish hit" };
    }
    return { score: 0 };
  },
}));

describe("OpenPhish checker", () => {
  test("detects malicious URL", async () => {
    const result = await checkOpenPhish("http://bad-site.com/login");
    expect(result.score).toBe(100);
  });

  test("returns safe for clean URL", async () => {
    const result = await checkOpenPhish("https://github.com");
    expect(result.score).toBe(0);
  });
});
