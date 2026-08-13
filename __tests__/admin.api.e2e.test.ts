const request = require("supertest");

import { createApp } from "../src/app";
import { hashApiKey } from "../src/utils/apiKeys";

const ADMIN_KEY = "ph_admin_test_key_abc123";

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
    resetStores: () => {
      store.clear();
      zset.clear();
    },
    default: {
      hset: jest.fn(
        async (
          key: string,
          data: Record<string, string> | string,
          ...rest: any[]
        ) => {
          if (typeof data === "object") {
            writeHset(key, data);
            return Object.keys(data).length;
          }
          const args = [data, ...rest] as string[];
          if (!store.has(key)) store.set(key, new Map());
          const map = store.get(key);
          for (let i = 0; i < args.length; i += 2)
            map.set(args[i], String(args[i + 1]));
          return args.length / 2;
        },
      ),
      hget: jest.fn(async (key: string, field: string) => {
        const map = store.get(key);
        return map ? (map.get(field) ?? null) : null;
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
      zadd: jest.fn(async (key: string, ...args: any[]) => {
        if (!zset.has(key)) zset.set(key, new Map());
        const map = zset.get(key)!;
        if (
          args.length === 1 &&
          typeof args[0] === "object" &&
          args[0] !== null
        ) {
          const { score, member } = args[0];
          map.set(member, score);
          return 1;
        }
        if (args.length >= 2) {
          const score = args[0];
          const member = args[1];
          map.set(member, score);
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
  process.env.ADMIN_API_KEY = ADMIN_KEY;
  app = createApp();
});

beforeEach(() => {
  jest.clearAllMocks();
  const mockRedis = jest.requireMock("../src/utils/redis") as {
    resetStores: () => void;
  };
  mockRedis.resetStores();
});

afterAll(() => {
  delete process.env.ADMIN_API_KEY;
});

describe("Admin API Key Management Endpoints", () => {
  describe("POST /admin/keys", () => {
    it("creates a new API key when authenticated as admin", async () => {
      const res = await request(app)
        .post("/admin/keys")
        .set("Authorization", `Bearer ${ADMIN_KEY}`)
        .send({ name: "my-app", tier: "pro" });

      expect(res.status).toBe(201);
      expect(res.body.apiKey).toMatch(/^ph_/);
      expect(res.body.metadata.name).toBe("my-app");
      expect(res.body.metadata.tier).toBe("pro");
      expect(res.body.metadata.enabled).toBe(true);
    });

    it("defaults to free tier when no tier is specified", async () => {
      const res = await request(app)
        .post("/admin/keys")
        .set("Authorization", `Bearer ${ADMIN_KEY}`)
        .send({ name: "default-tier" });

      expect(res.status).toBe(201);
      expect(res.body.metadata.tier).toBe("free");
    });

    it("rejects request without name", async () => {
      const res = await request(app)
        .post("/admin/keys")
        .set("Authorization", `Bearer ${ADMIN_KEY}`)
        .send({ tier: "pro" });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/name/i);
    });

    it("rejects request without admin auth", async () => {
      const res = await request(app)
        .post("/admin/keys")
        .send({ name: "no-auth", tier: "free" });

      expect(res.status).toBe(401);
    });

    it("rejects request with non-admin API key", async () => {
      const { createApiKey } = require("../src/utils/apiKeys");
      const { apiKey } = await createApiKey("regular-user", "free");

      const res = await request(app)
        .post("/admin/keys")
        .set("Authorization", `Bearer ${apiKey}`)
        .send({ name: "should-not-work", tier: "free" });

      expect(res.status).toBe(401);
    });
  });

  describe("GET /admin/keys", () => {
    it("lists all API keys", async () => {
      const { createApiKey } = require("../src/utils/apiKeys");
      await createApiKey("key-one", "free");
      await createApiKey("key-two", "pro");

      const res = await request(app)
        .get("/admin/keys")
        .set("Authorization", `Bearer ${ADMIN_KEY}`);

      expect(res.status).toBe(200);
      expect(res.body.keys).toBeDefined();
      expect(res.body.keys).toHaveLength(2);
      const names = res.body.keys.map((k: any) => k.name).sort();
      expect(names).toEqual(["key-one", "key-two"]);
    });

    it("does not expose full apiKey values in the listing", async () => {
      const res = await request(app)
        .get("/admin/keys")
        .set("Authorization", `Bearer ${ADMIN_KEY}`);

      expect(res.status).toBe(200);
      for (const key of res.body.keys) {
        expect(key.apiKey).toBeUndefined();
      }
    });

    it("returns empty list when no keys exist", async () => {
      const res = await request(app)
        .get("/admin/keys")
        .set("Authorization", `Bearer ${ADMIN_KEY}`);

      expect(res.status).toBe(200);
      expect(res.body.keys).toEqual([]);
    });

    it("rejects without admin auth", async () => {
      const res = await request(app).get("/admin/keys");
      expect(res.status).toBe(401);
    });
  });

  describe("GET /admin/keys/:hash", () => {
    it("returns details for a specific key", async () => {
      const { createApiKey } = require("../src/utils/apiKeys");
      const { apiKey, metadata } = await createApiKey(
        "specific-key",
        "enterprise",
      );
      const hash = hashApiKey(apiKey);

      const res = await request(app)
        .get(`/admin/keys/${hash}`)
        .set("Authorization", `Bearer ${ADMIN_KEY}`);

      expect(res.status).toBe(200);
      expect(res.body.name).toBe("specific-key");
      expect(res.body.tier).toBe("enterprise");
    });

    it("returns 404 for non-existent hash", async () => {
      const res = await request(app)
        .get("/admin/keys/nonexistenthash123")
        .set("Authorization", `Bearer ${ADMIN_KEY}`);

      expect(res.status).toBe(404);
    });
  });

  describe("PATCH /admin/keys/:hash", () => {
    it("updates a key's tier", async () => {
      const { createApiKey } = require("../src/utils/apiKeys");
      const { apiKey } = await createApiKey("upgrade-me", "free");
      const hash = hashApiKey(apiKey);

      const res = await request(app)
        .patch(`/admin/keys/${hash}`)
        .set("Authorization", `Bearer ${ADMIN_KEY}`)
        .send({ tier: "pro" });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      const check = await request(app)
        .get(`/admin/keys/${hash}`)
        .set("Authorization", `Bearer ${ADMIN_KEY}`);
      expect(check.body.tier).toBe("pro");
    });

    it("disables a key", async () => {
      const { createApiKey } = require("../src/utils/apiKeys");
      const { apiKey } = await createApiKey("disable-key", "free");
      const hash = hashApiKey(apiKey);

      const res = await request(app)
        .patch(`/admin/keys/${hash}`)
        .set("Authorization", `Bearer ${ADMIN_KEY}`)
        .send({ enabled: false });

      expect(res.status).toBe(200);

      const check = await request(app)
        .get(`/admin/keys/${hash}`)
        .set("Authorization", `Bearer ${ADMIN_KEY}`);
      expect(check.body.enabled).toBe(false);
    });

    it("returns 404 for non-existent hash", async () => {
      const res = await request(app)
        .patch("/admin/keys/noexist")
        .set("Authorization", `Bearer ${ADMIN_KEY}`)
        .send({ name: "noop" });

      expect(res.status).toBe(404);
    });

    it("rejects without admin auth", async () => {
      const res = await request(app)
        .patch("/admin/keys/somehash")
        .send({ name: "nope" });
      expect(res.status).toBe(401);
    });
  });

  describe("DELETE /admin/keys/:hash", () => {
    it("deletes an API key", async () => {
      const { createApiKey } = require("../src/utils/apiKeys");
      const { apiKey } = await createApiKey("delete-me", "free");
      const hash = hashApiKey(apiKey);

      const res = await request(app)
        .delete(`/admin/keys/${hash}`)
        .set("Authorization", `Bearer ${ADMIN_KEY}`);

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      const check = await request(app)
        .get(`/admin/keys/${hash}`)
        .set("Authorization", `Bearer ${ADMIN_KEY}`);
      expect(check.status).toBe(404);
    });

    it("returns 404 for non-existent hash", async () => {
      const res = await request(app)
        .delete("/admin/keys/noexist")
        .set("Authorization", `Bearer ${ADMIN_KEY}`);

      expect(res.status).toBe(404);
    });

    it("rejects without admin auth", async () => {
      const res = await request(app).delete("/admin/keys/somehash");
      expect(res.status).toBe(401);
    });
  });
});
