import * as openphish from "../src/checkers/openphish";

jest
  .spyOn(openphish as any, "loadOpenPhish")
  .mockResolvedValue([
    "http://bad-site.com/login",
    "https://evil.example/phish",
  ]);

describe("OpenPhish checker", () => {
  test("detects URL in OpenPhish feed", async () => {
    const result = await openphish.checkOpenPhish("http://bad-site.com/login");

    expect(result.score).toBe(100);
    expect(result.reason).toMatch(/OpenPhish/i);
  });

  test("returns safe for unknown URL", async () => {
    const result = await openphish.checkOpenPhish("https://github.com");

    expect(result.score).toBe(0);
  });
});
