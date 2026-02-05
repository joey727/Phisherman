import { safeResolveHost, blockIfPrivate } from "../src/utils//network";

describe("Network SSRF protection", () => {
  test("blocks private IP", () => {
    expect(() => blockIfPrivate("192.168.1.1")).toThrow();
  });

  test("allows public IP", () => {
    expect(() => blockIfPrivate("8.8.8.8")).not.toThrow();
  });

  test("blocks domain resolving to private IP", async () => {
    jest
      .spyOn(require("node:dns/promises"), "lookup")
      .mockResolvedValue([{ address: "127.0.0.1", family: 4 }]);

    await expect(safeResolveHost("evil.local")).rejects.toThrow();
  });
});
