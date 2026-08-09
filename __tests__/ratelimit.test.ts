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
  return {
    apiKey: opts?.apiKey,
    ip: opts?.ip || "127.0.0.1",
    headers: {},
    socket: { remoteAddress: "127.0.0.1" },
  } as unknown as Request;
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

  it("uses IP-based rate limit key when no apiKey is present", async () => {
    mockPipeline.exec.mockResolvedValue([1, 1]);
    const req = mockReq({ ip: "10.0.0.1" });
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await apiLimiter(req, res, next);

    expect(mockPipeline.incr).toHaveBeenCalledWith("ratelimit:10.0.0.1");
    expect(mockPipeline.expire).toHaveBeenCalledWith("ratelimit:10.0.0.1", 86400);
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

  it("returns 429 when rate limit is exceeded for anonymous", async () => {
    mockPipeline.exec.mockResolvedValue([150, 1]);
    const req = mockReq({ ip: "10.0.0.2" });
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await apiLimiter(req, res, next);

    expect(res.status).toHaveBeenCalledWith(429);
    expect(next).not.toHaveBeenCalled();
  });

  it("returns 429 when rate limit is exceeded for an api key", async () => {
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

    expect(res.status).toHaveBeenCalledWith(429);
    expect(next).not.toHaveBeenCalled();
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

    expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Limit", "1");
    expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Remaining", "0");
    expect(res.setHeader).toHaveBeenCalledWith("X-RateLimit-Reset", "86400");
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
