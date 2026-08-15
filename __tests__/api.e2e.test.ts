const request = require("supertest");

import { createApp } from "../src/app";
import { analyzeUrl } from "../src/Scanner";
import redis from "../src/utils/redis";

jest.mock("../src/Scanner", () => ({
  analyzeUrl: jest.fn(),
}));

jest.mock("../src/utils/redis", () => {
  const pipeline = {
    incr: jest.fn().mockReturnThis(),
    expire: jest.fn().mockReturnThis(),
    exec: jest.fn().mockResolvedValue([1, 1]),
  };

  return {
    __esModule: true,
    default: {
      pipeline: jest.fn(() => pipeline),
      get: jest.fn().mockResolvedValue("0"),
      llen: jest.fn().mockResolvedValue(0),
    },
  };
});

describe("API e2e", () => {
  const app = createApp();
  const mockedAnalyzeUrl = analyzeUrl as jest.MockedFunction<typeof analyzeUrl>;
  const mockedRedis = redis as unknown as jest.Mocked<any>;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("returns health status without Redis access", async () => {
    const res = await request(app).get("/health");

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: "ok" });
    expect(mockedRedis.get).not.toHaveBeenCalled();
  });

  it("validates check payloads", async () => {
    const res = await request(app).post("/api/check").send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/Missing 'url'/);
    expect(mockedAnalyzeUrl).not.toHaveBeenCalled();
  });

  it("runs URL analysis through the HTTP API", async () => {
    mockedAnalyzeUrl.mockResolvedValueOnce({
      url: "https://example.com",
      score: 0,
      verdict: "safe",
      reasons: [],
      executionTimeMs: {},
    });

    const res = await request(app)
      .post("/api/check")
      .send({ url: "https://example.com" });

    expect(res.status).toBe(200);
    expect(res.body.verdict).toBe("safe");
    expect(mockedAnalyzeUrl).toHaveBeenCalledWith("https://example.com", {
      tier: "free",
      enableMl: false,
      degraded: false,
    });
  });
});
