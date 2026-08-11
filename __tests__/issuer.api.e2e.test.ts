const request = require("supertest");

import { createApp } from "../src/app";

const ISSUER_KEY = "issuer_test_key_xyz789";

let app: ReturnType<typeof createApp>;

jest.mock("../src/Scanner", () => ({
  analyzeUrl: jest.fn(),
}));

jest.mock("../src/utils/redis", () => {
  const store = new Map<string, any>();
  const zset = new Map<string, Map<string, number>>();

  function writeHset(key: string, data: Record<string, string>) {
    if (!store.has(key)) store.set(key, new Map<string, string>());
    const map = store.get(key);
    for (const [k, v] of Object.entries(data)) map.set(k, String(v));
  }

  return {
    __esModule: true,
    resetStores: () => { store.clear(); zset.clear(); },
    default: {
      hset: jest.fn(async (key: string, data: Record<string, string>) => {
        writeHset(key, data);
        return Object.keys(data).length;
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
      hdel: jest.fn(async (key: string, ...fields: string[]) => {
        const map = store.get(key);
        if (!map) return 0;
        let count = 0;
        for (const f of fields) if (map.delete(f)) count++;
        return count;
      }),
      zadd: jest.fn(async (key: string, args: { score: number; member: string }) => {
        if (!zset.has(key)) zset.set(key, new Map());
        const map = zset.get(key)!;
        if (args && typeof args === "object" && "score" in args) {
          map.set(args.member, args.score);
          return 1;
        }
        return 0;
      }),
      zrange: jest.fn(async (key: string, start: number, stop: number) => {
        const map = zset.get(key);
        if (!map) return [];
        const entries = [...map.entries()].sort((a, b) => a[1] - b[1]);
        const end = stop === -1 ? entries.length - 1 : start + stop;
        return entries.slice(start, end + 1).map(([m]) => m);
      }),
      zrem: jest.fn(async (key: string, ...members: string[]) => {
        const map = zset.get(key);
        if (!map) return 0;
        let count = 0;
        for (const m of members) if (map.delete(m)) count++;
        return count;
      }),
      exists: jest.fn(async (...keys: string[]) => {
        let count = 0;
        for (const k of keys) {
          if (store.has(k) || zset.has(k)) count++;
        }
        return count;
      }),
      del: jest.fn(async (...keys: string[]) => {
        let count = 0;
        for (const k of keys) {
          if (store.delete(k) || zset.delete(k)) count++;
        }
        return count;
      }),
      pipeline: jest.fn(() => ({
        incr: jest.fn().mockReturnThis(),
        expire: jest.fn().mockReturnThis(),
        exec: jest.fn().mockResolvedValue([1, 1]),
      })),
      get: jest.fn().mockResolvedValue("0"),
      llen: jest.fn().mockResolvedValue(0),
    },
  };
});

beforeAll(() => {
  process.env.ISSUER_API_KEY = ISSUER_KEY;
  app = createApp();
});

beforeEach(() => {
  jest.clearAllMocks();
  const mockRedis = jest.requireMock("../src/utils/redis") as { resetStores: () => void };
  mockRedis.resetStores();
});

afterAll(() => {
  delete process.env.ISSUER_API_KEY;
});

describe("Issuer API Key Endpoint (mint-only, POST /keys)", () => {
  it("creates a key when authenticated as issuer", async () => {
    const res = await request(app)
      .post("/keys")
      .set("Authorization", `Bearer ${ISSUER_KEY}`)
      .send({ name: "my-app", email: "dev@example.com", tier: "pro" });

    expect(res.status).toBe(201);
    expect(res.body.apiKey).toMatch(/^ph_/);
    expect(res.body.metadata.name).toBe("my-app");
    expect(res.body.metadata.email).toBe("dev@example.com");
    expect(res.body.metadata.tier).toBe("pro");
    expect(res.body.metadata.enabled).toBe(true);
  });

  it("defaults to free tier when no tier is specified", async () => {
    const res = await request(app)
      .post("/keys")
      .set("Authorization", `Bearer ${ISSUER_KEY}`)
      .send({ name: "default-tier" });

    expect(res.status).toBe(201);
    expect(res.body.metadata.tier).toBe("free");
  });

  it("rejects a request without a name", async () => {
    const res = await request(app)
      .post("/keys")
      .set("Authorization", `Bearer ${ISSUER_KEY}`)
      .send({ tier: "pro" });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/name/i);
  });

  it("rejects an invalid email", async () => {
    const res = await request(app)
      .post("/keys")
      .set("Authorization", `Bearer ${ISSUER_KEY}`)
      .send({ name: "bad-email", email: "not-an-email" });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/email/i);
  });

  it("rejects a request with the wrong issuer key", async () => {
    const res = await request(app)
      .post("/keys")
      .set("Authorization", "Bearer wrong_issuer_key")
      .send({ name: "nope" });

    expect(res.status).toBe(401);
  });

  it("rejects a request without any auth", async () => {
    const res = await request(app).post("/keys").send({ name: "nope" });
    expect(res.status).toBe(401);
  });

  it("rejects a regular ph_ API key (cannot mint)", async () => {
    const { createApiKey } = require("../src/utils/apiKeys");
    const { apiKey } = await createApiKey("regular-user", "free");

    const res = await request(app)
      .post("/keys")
      .set("Authorization", `Bearer ${apiKey}`)
      .send({ name: "should-not-work" });

    expect(res.status).toBe(401);
  });

  it("fails closed when ISSUER_API_KEY is not configured", async () => {
    delete process.env.ISSUER_API_KEY;
    const withoutConfig = createApp();

    const res = await request(withoutConfig)
      .post("/keys")
      .set("Authorization", `Bearer ${ISSUER_KEY}`)
      .send({ name: "no-config" });

    expect(res.status).toBe(503);
    process.env.ISSUER_API_KEY = ISSUER_KEY;
  });
});

describe("GET /api/keys/validate", () => {
  it("validates a real API key and returns its tier", async () => {
    const { createApiKey } = require("../src/utils/apiKeys");
    const { apiKey } = await createApiKey("tester", "pro");

    const res = await request(app)
      .get("/api/keys/validate")
      .set("Authorization", `Bearer ${apiKey}`);

    expect(res.status).toBe(200);
    expect(res.body.valid).toBe(true);
    expect(res.body.tier).toBe("pro");
    expect(res.body.name).toBe("tester");
    expect(res.body.enabled).toBe(true);
  });

  it("rejects an unknown API key", async () => {
    const res = await request(app)
      .get("/api/keys/validate")
      .set("Authorization", "Bearer ph_doesnotexist1234567890");

    expect(res.status).toBe(401);
    expect(res.body.valid).toBe(false);
  });

  it("rejects a request without a key", async () => {
    const res = await request(app).get("/api/keys/validate");
    expect(res.status).toBe(401);
    expect(res.body.valid).toBe(false);
  });

  it("rejects a disabled key", async () => {
    const { createApiKey, updateApiKey, hashApiKey } = require("../src/utils/apiKeys");
    const { apiKey } = await createApiKey("disabled-user", "free");
    await updateApiKey(hashApiKey(apiKey), { enabled: false });

    const res = await request(app)
      .get("/api/keys/validate")
      .set("Authorization", `Bearer ${apiKey}`);

    expect(res.status).toBe(401);
    expect(res.body.valid).toBe(false);
  });
});