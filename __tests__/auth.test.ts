import { Request, Response, NextFunction } from "express";
import { authMiddleware } from "../src/middleware/auth";
import { createApiKey, verifyApiKey } from "../src/utils/apiKeys";
import redis from "../src/utils/redis";

jest.mock("../src/utils/redis", () => {
  const store = new Map<string, any>();
  const zset = new Map<string, Map<string, number>>();
  return {
    __esModule: true,
    resetStores: () => { store.clear(); zset.clear(); },
    default: {
      hset: jest.fn(async (key: string, data: Record<string, string> | string, ...rest: any[]) => {
        if (!store.has(key)) store.set(key, new Map<string, string>());
        const map = store.get(key);
        if (typeof data === "object" && !Array.isArray(data)) {
          for (const [k, v] of Object.entries(data)) map.set(k, String(v));
          return Object.keys(data).length;
        }
        const args = [data, ...rest] as string[];
        for (let i = 0; i < args.length; i += 2) map.set(args[i], String(args[i + 1]));
        return args.length / 2;
      }),
      hget: jest.fn(async (key: string, field: string) => {
        const map = store.get(key);
        return map ? map.get(field) ?? null : null;
      }),
      hgetall: jest.fn(async (key: string) => {
        const map = store.get(key);
        if (!map) return null;
        const obj: Record<string, string> = {};
        for (const [k, v] of map) obj[k] = v;
        return obj;
      }),
      exists: jest.fn(async (...keys: string[]) => {
        let count = 0;
        for (const k of keys) { if (store.has(k) || zset.has(k)) count++; }
        return count;
      }),
      zadd: jest.fn(async (key: string, ...args: any[]) => {
        if (!zset.has(key)) zset.set(key, new Map());
        const map = zset.get(key)!;
        if (args.length === 2) { const [score, member] = args; map.set(member, score); return 1; }
        return 0;
      }),
    },
  };
});

const OLD_ENV = process.env;

function mockReq(authHeader?: string): Request {
  return {
    headers: authHeader ? { authorization: authHeader } : {},
    ip: "127.0.0.1",
    socket: { remoteAddress: "127.0.0.1" },
  } as unknown as Request;
}

function mockRes(): Response {
  const res: Partial<Response> = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res as Response;
}

describe("auth middleware", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    process.env = { ...OLD_ENV, ADMIN_API_KEY: "" };
    const mockModule = jest.requireMock("../src/utils/redis") as { resetStores?: () => void };
    mockModule.resetStores?.();
  });

  afterAll(() => {
    process.env = OLD_ENV;
  });

  it("passes through without auth header (anonymous)", async () => {
    const req = mockReq();
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await authMiddleware(req, res, next);

    expect(req.apiKey).toBeUndefined();
    expect(req.isAdmin).toBeUndefined();
    expect(next).toHaveBeenCalled();
  });

  it("passes through with empty auth header", async () => {
    const req = mockReq("Bearer ");
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await authMiddleware(req, res, next);

    expect(req.apiKey).toBeUndefined();
    expect(next).toHaveBeenCalled();
  });

  it("attaches apiKey metadata for a valid API key", async () => {
    const { apiKey } = await createApiKey("test-user", "pro");

    const req = mockReq(`Bearer ${apiKey}`);
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await authMiddleware(req, res, next);

    expect(req.apiKey).toBeDefined();
    expect(req.apiKey!.name).toBe("test-user");
    expect(req.apiKey!.tier).toBe("pro");
    expect(req.apiKey!.enabled).toBe(true);
    expect(req.isAdmin).toBeUndefined();
    expect(next).toHaveBeenCalled();
  });

  it("passes through for a revoked/disabled API key (no block)", async () => {
    const { apiKey } = await createApiKey("revoked-user", "free");
    const hash = require("../src/utils/apiKeys").hashApiKey(apiKey);
    await require("../src/utils/apiKeys").updateApiKey(hash, { enabled: false });

    const req = mockReq(`Bearer ${apiKey}`);
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await authMiddleware(req, res, next);

    expect(req.apiKey).toBeUndefined();
    expect(next).toHaveBeenCalled();
  });

  it("passes through for a malformed key", async () => {
    const req = mockReq("Bearer not-a-real-key");
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await authMiddleware(req, res, next);

    expect(req.apiKey).toBeUndefined();
    expect(next).toHaveBeenCalled();
  });

  it("sets isAdmin when the bearer token matches ADMIN_API_KEY env var", async () => {
    process.env.ADMIN_API_KEY = "ph_admin_super_secret_key_12345";

    const req = mockReq("Bearer ph_admin_super_secret_key_12345");
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await authMiddleware(req, res, next);

    expect(req.isAdmin).toBe(true);
    expect(req.apiKey).toBeUndefined();
    expect(next).toHaveBeenCalled();
  });

  it("does not set isAdmin for non-admin API keys", async () => {
    const { apiKey } = await createApiKey("regular-user", "free");

    const req = mockReq(`Bearer ${apiKey}`);
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await authMiddleware(req, res, next);

    expect(req.isAdmin).toBeUndefined();
    expect(next).toHaveBeenCalled();
  });

  it("sets req.apiKey for a valid key AND req.isAdmin if it matches ADMIN_API_KEY", async () => {
    const { apiKey } = await createApiKey("also-admin", "enterprise");
    process.env.ADMIN_API_KEY = apiKey;

    const req = mockReq(`Bearer ${apiKey}`);
    const res = mockRes();
    const next: NextFunction = jest.fn();

    await authMiddleware(req, res, next);

    expect(req.isAdmin).toBe(true);
    expect(req.apiKey).toBeDefined();
    expect(req.apiKey!.name).toBe("also-admin");
    expect(next).toHaveBeenCalled();
  });
});
