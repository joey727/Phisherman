import { Request, Response, NextFunction } from "express";
import { apiLimiter } from "../src/middleware/ratelimit";
import { ApiKeyMetadata } from "../src/types";

const mockPipeline = {
  incr: jest.fn().mockReturnThis(),
  expire: jest.fn().mockReturnThis(),
  exec: jest.fn(),
};

jest.mock("../src/utils/redis", () => ({
  __esModule: true,
  default: {
    pipeline: jest.fn(() => mockPipeline),
  },
}));

function mockReq(opts?: {
  apiKey?: ApiKeyMetadata;
  ip?: string;
}): Request {
  const req = {
    apiKey: opts?.apiKey,
    ip: opts?.ip || "127.0.0.1",
    headers: {},
    socket: { remoteAddress: "127.0.0.1" },
  } as unknown as Request;
  req.degradedQuota = false;
  return req;
}

function mockRes(): Response {
  const res: Partial<Response> = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  res.on = jest.fn().mockReturnValue(res);
  res.removeListener = jest.fn().mockReturnValue(res);
  res.setHeader = jest.fn().mockReturnValue(res);
  return res as unknown as Response;
}

describe("apiLimiter", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("skips the windowed quota for anonymous requests (free, no rate limit)", async () => {
    const req = mockReq({ ip: "10.0.0.1" });
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await apiLimiter(req, res, next);

    expect(mockPipeline.incr).not.toHaveBeenCalled();
    expect(mockPipeline.expire).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalled();
  });

  it("uses key hash as the rate limit key when apiKey is present", async () => {
    mockPipeline.exec.mockResolvedValue([1, 1]);
    const apiKey: ApiKeyMetadata = {
      hash: "abc123def456",
      prefix: "ph_test_",
      name: "test-key",
      tier: "free",
      enabled: true,
      createdAt: 1000,
      lastUsedAt: null,
    };
    const req = mockReq({ apiKey, ip: "10.0.0.1" });
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await apiLimiter(req, res, next);

    expect(mockPipeline.incr).toHaveBeenCalledWith("ratelimit:key:abc123def456");
    expect(mockPipeline.expire).toHaveBeenCalledWith("ratelimit:key:abc123def456", 86400);
    expect(next).toHaveBeenCalled();
  });

  it("applies tier-specific rate limit windows", async () => {
    mockPipeline.exec.mockResolvedValue([1, 1]);
    const enterpriseKey: ApiKeyMetadata = {
      hash: "enterprise_hash",
      prefix: "ph_ent_",
      name: "enterprise-user",
      tier: "enterprise",
      enabled: true,
      createdAt: 1000,
      lastUsedAt: null,
    };
    const req = mockReq({ apiKey: enterpriseKey });
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await apiLimiter(req, res, next);

    expect(mockPipeline.expire).toHaveBeenCalledWith(
      "ratelimit:key:enterprise_hash",
      86400,
    );
    expect(next).toHaveBeenCalled();
  });

  it("degrades instead of 429 when quota is exceeded for an api key", async () => {
    mockPipeline.exec.mockResolvedValue([2000, 1]);
    const apiKey: ApiKeyMetadata = {
      hash: "overuser_hash",
      prefix: "ph_over",
      name: "over-user",
      tier: "free",
      enabled: true,
      createdAt: 1000,
      lastUsedAt: null,
    };
    const req = mockReq({ apiKey });
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await apiLimiter(req, res, next);

    expect(req.degradedQuota).toBe(true);
    expect(res.status).not.toHaveBeenCalledWith(429);
    expect(next).toHaveBeenCalled();
  });

  it("calls next() when Redis errors occur (graceful degradation)", async () => {
    mockPipeline.exec.mockRejectedValue(new Error("Redis connection lost"));
    const req = mockReq({ ip: "10.0.0.3" });
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await apiLimiter(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it("sets X-RateLimit headers on success for anonymous", async () => {
    mockPipeline.exec.mockResolvedValue([1, 1]);
    const req = mockReq({ ip: "10.0.0.4" });
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await apiLimiter(req, res, next);

    expect(res.setHeader).not.toHaveBeenCalledWith("X-RateLimit-Limit", "1");
    expect(next).toHaveBeenCalled();
  });

  it("sets X-RateLimit headers reflecting remaining quota for a free key", async () => {
    mockPipeline.exec.mockResolvedValue([2, 1]);
    const apiKey: ApiKeyMetadata = {
      hash: "free_user_hash",
      prefix: "ph_free",
      name: "free-user",
      tier: "free",
      enabled: true,
      createdAt: 1000,
      lastUsedAt: null,
    };
    const req = mockReq({ apiKey });
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await apiLimiter(req, res, next);

    expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Limit", "3");
    expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Remaining", "1");
    expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Reset", "86400");
    expect(next).toHaveBeenCalled();
  });
});
