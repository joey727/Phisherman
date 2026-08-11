import {
  generateApiKey,
  hashApiKey,
  createApiKey,
  getApiKey,
  listApiKeys,
  updateApiKey,
  deleteApiKey,
  verifyApiKey,
} from "../src/utils/apiKeys";
import redis from "../src/utils/redis";

function buildMockRedis() {
  const store = new Map<string, any>();
  const zset = new Map<string, Map<string, number>>();

  function createPipeline() {
    const commands: Array<{ cmd: string; args: any[] }> = [];
    const pipe = {
      hset: jest.fn((key: string, data: Record<string, string>) => {
        commands.push({ cmd: "hset", args: [key, data] });
        return pipe;
      }),
      zadd: jest.fn((key: string, score: number, member: string) => {
        commands.push({ cmd: "zadd", args: [key, score, member] });
        return pipe;
      }),
      del: jest.fn((...keys: string[]) => {
        commands.push({ cmd: "del", args: keys });
        return pipe;
      }),
      zrem: jest.fn((key: string, ...members: string[]) => {
        commands.push({ cmd: "zrem", args: [key, ...members] });
        return pipe;
      }),
      exec: jest.fn(async () => {
        const results: any[] = [];
        for (const { cmd, args } of commands) {
          if (cmd === "hset") {
            const [key, data] = args;
            if (!store.has(key)) store.set(key, new Map<string, string>());
            const map = store.get(key);
            for (const [k, v] of Object.entries(data)) {
              map.set(k, String(v));
            }
            results.push(Object.keys(data).length);
          } else if (cmd === "zadd") {
            const [key, score, member] = args;
            if (!zset.has(key)) zset.set(key, new Map());
            zset.get(key)!.set(member, score);
            results.push(1);
          } else if (cmd === "del") {
            let count = 0;
            for (const k of args) {
              if (store.delete(k) || zset.delete(k)) count++;
            }
            results.push(count);
          } else if (cmd === "zrem") {
            const [key, ...members] = args;
            const map = zset.get(key);
            if (!map) { results.push(0); continue; }
            let count = 0;
            for (const m of members) {
              if (map.delete(m)) count++;
            }
            results.push(count);
          }
        }
        return results;
      }),
    };
    return pipe;
  }

  return {
    __esModule: true,
    default: {
      hset: jest.fn(async (key: string, data: Record<string, string> | string, ...rest: any[]) => {
        if (!store.has(key)) store.set(key, new Map<string, string>());
        const map = store.get(key);
        if (typeof data === "object" && !Array.isArray(data)) {
          for (const [k, v] of Object.entries(data)) {
            map.set(k, String(v));
          }
          return Object.keys(data).length;
        }
        const args = [data, ...rest] as string[];
        for (let i = 0; i < args.length; i += 2) {
          map.set(args[i], String(args[i + 1]));
        }
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
      hdel: jest.fn(async (key: string, ...fields: string[]) => {
        const map = store.get(key);
        if (!map) return 0;
        let count = 0;
        for (const f of fields) {
          if (map.delete(f)) count++;
        }
        return count;
      }),
      zadd: jest.fn(async (key: string, ...args: any[]) => {
        if (!zset.has(key)) zset.set(key, new Map());
        const map = zset.get(key)!;
        if (args.length === 1 && typeof args[0] === "object" && args[0] !== null) {
          const { score, member } = args[0];
          map.set(member, score);
          return 1;
        }
        if (args.length === 2) {
          const [score, member] = args;
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
        for (const m of members) {
          if (map.delete(m)) count++;
        }
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
      pipeline: jest.fn(() => createPipeline()),
    },
    resetStores: () => {
      store.clear();
      zset.clear();
    },
  };
};

jest.mock("../src/utils/redis", () => buildMockRedis());

describe("apiKeys utility", () => {
  const mockedRedis = redis as unknown as jest.Mocked<any>;

  beforeEach(() => {
    jest.clearAllMocks();
    const mockModule = jest.requireMock("../src/utils/redis") as { resetStores?: () => void };
    mockModule.resetStores?.();
  });

  describe("generateApiKey", () => {
    it("returns a key starting with ph_", () => {
      const key = generateApiKey();
      expect(key).toMatch(/^ph_/);
    });

    it("returns a key of expected length (ph_ + 64 base64url chars)", () => {
      const key = generateApiKey();
      expect(key.length).toBeGreaterThan(60);
      expect(key.length).toBeLessThan(80);
    });

    it("produces unique keys on successive calls", () => {
      const key1 = generateApiKey();
      const key2 = generateApiKey();
      expect(key1).not.toBe(key2);
    });
  });

  describe("hashApiKey", () => {
    it("returns a hex string of 64 characters (SHA-256)", () => {
      const hash = hashApiKey("ph_test_key_value");
      expect(hash).toMatch(/^[a-f0-9]{64}$/);
    });

    it("returns the same hash for the same input", () => {
      const hash1 = hashApiKey("ph_some_key");
      const hash2 = hashApiKey("ph_some_key");
      expect(hash1).toBe(hash2);
    });

    it("different keys produce different hashes", () => {
      const hash1 = hashApiKey("ph_key_one");
      const hash2 = hashApiKey("ph_key_two");
      expect(hash1).not.toBe(hash2);
    });
  });

  describe("createApiKey", () => {
    it("stores a key in Redis and returns its metadata with the raw key", async () => {
      const result = await createApiKey("test-key", "free");

      expect(result).toBeDefined();
      expect(result.apiKey).toMatch(/^ph_/);
      expect(result.metadata.name).toBe("test-key");
      expect(result.metadata.tier).toBe("free");
      expect(result.metadata.enabled).toBe(true);
      expect(result.metadata.createdAt).toBeGreaterThan(0);
      expect(result.metadata.lastUsedAt).toBeNull();
      expect(result.metadata.prefix).toBe(result.apiKey.substring(0, 8));
    });

    it("stores metadata in a Redis hash keyed by the SHA-256 hash", async () => {
      const { apiKey, metadata } = await createApiKey("hash-key", "pro");
      const hash = hashApiKey(apiKey);

      const stored = await mockedRedis.hgetall(`apikey:${hash}`);
      expect(stored).not.toBeNull();
      expect(stored.name).toBe("hash-key");
      expect(stored.tier).toBe("pro");
      expect(stored.enabled).toBe("true");
    });

    it("adds the hash to the apikeys ZSET", async () => {
      const { apiKey, metadata } = await createApiKey("zset-test", "enterprise");
      const hash = hashApiKey(apiKey);

      expect(mockedRedis.zadd).toHaveBeenCalledWith(
        "apikeys",
        { score: metadata.createdAt, member: hash },
      );
    });

    it("supports all tiers", async () => {
      for (const tier of ["free", "pro", "enterprise"] as const) {
        const { metadata } = await createApiKey(`tier-${tier}`, tier);
        expect(metadata.tier).toBe(tier);
      }
    });
  });

  describe("getApiKey", () => {
    it("returns metadata for an existing key", async () => {
      const { apiKey, metadata } = await createApiKey("get-me", "free");
      const hash = hashApiKey(apiKey);

      const result = await getApiKey(hash);
      expect(result).not.toBeNull();
      expect(result!.name).toBe("get-me");
      expect(result!.tier).toBe("free");
    });

    it("returns null for a non-existent hash", async () => {
      const result = await getApiKey("nonexistenthash1234567890123456789012345678901234567890123456789012345678901234");
      expect(result).toBeNull();
    });

    it("treats a boolean-true enabled field (as deserialized by @upstash/redis) as enabled", async () => {
      const { apiKey, metadata } = await createApiKey("bool-enabled", "pro");
      const hash = hashApiKey(apiKey);
      mockedRedis.hgetall.mockResolvedValueOnce({
        name: "bool-enabled",
        prefix: metadata.prefix,
        tier: "pro",
        enabled: true,
        createdAt: metadata.createdAt,
        lastUsedAt: "",
      });

      const result = await getApiKey(hash);
      expect(result).not.toBeNull();
      expect(result!.enabled).toBe(true);
    });
  });

  describe("listApiKeys", () => {
    it("returns an empty array when no keys exist", async () => {
      const keys = await listApiKeys();
      expect(keys).toEqual([]);
    });

    it("returns all stored api key metadata", async () => {
      const { metadata: m1 } = await createApiKey("key-a", "free");
      const { metadata: m2 } = await createApiKey("key-b", "pro");
      const { metadata: m3 } = await createApiKey("key-c", "enterprise");

      const keys = await listApiKeys();
      expect(keys).toHaveLength(3);
      const names = keys.map((k) => k.name).sort();
      expect(names).toEqual(["key-a", "key-b", "key-c"]);
    });
  });

  describe("updateApiKey", () => {
    it("updates the tier of an existing key", async () => {
      const { apiKey, metadata } = await createApiKey("updatable", "free");
      const hash = hashApiKey(apiKey);

      await updateApiKey(hash, { tier: "pro" });

      const stored = await getApiKey(hash);
      expect(stored!.tier).toBe("pro");
    });

    it("disables an existing key", async () => {
      const { apiKey } = await createApiKey("disable-me", "free");
      const hash = hashApiKey(apiKey);

      await updateApiKey(hash, { enabled: false });

      const stored = await getApiKey(hash);
      expect(stored!.enabled).toBe(false);
    });

    it("renames an existing key", async () => {
      const { apiKey } = await createApiKey("old-name", "pro");
      const hash = hashApiKey(apiKey);

      await updateApiKey(hash, { name: "new-name" });

      const stored = await getApiKey(hash);
      expect(stored!.name).toBe("new-name");
    });

    it("returns false for a non-existent hash", async () => {
      const result = await updateApiKey("nonexistent", { name: "noop" });
      expect(result).toBe(false);
    });
  });

  describe("deleteApiKey", () => {
    it("removes the key hash and ZSET entry", async () => {
      const { apiKey, metadata } = await createApiKey("delete-me", "free");
      const hash = hashApiKey(apiKey);

      await deleteApiKey(hash);

      const stored = await getApiKey(hash);
      expect(stored).toBeNull();

      expect(mockedRedis.zrem).toHaveBeenCalledWith("apikeys", hash);
    });

    it("returns false for a non-existent hash", async () => {
      const result = await deleteApiKey("nonexistent");
      expect(result).toBe(false);
    });
  });

  describe("verifyApiKey", () => {
    it("returns metadata for a valid, enabled key", async () => {
      const { apiKey, metadata } = await createApiKey("valid-key", "free");

      const result = await verifyApiKey(apiKey);
      expect(result).not.toBeNull();
      expect(result!.name).toBe("valid-key");
      expect(result!.enabled).toBe(true);
    });

    it("returns null for a disabled key", async () => {
      const { apiKey } = await createApiKey("disabled-key", "free");
      const hash = hashApiKey(apiKey);
      await updateApiKey(hash, { enabled: false });

      const result = await verifyApiKey(apiKey);
      expect(result).toBeNull();
    });

    it("returns null for a malformed key", async () => {
      const result = await verifyApiKey("not-a-valid-key");
      expect(result).toBeNull();
    });

    it("returns null for a non-existent key", async () => {
      const result = await verifyApiKey("ph_abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
      expect(result).toBeNull();
    });

    it("updates lastUsedAt on successful verification", async () => {
      const { apiKey, metadata } = await createApiKey("track-usage", "free");
      const hash = hashApiKey(apiKey);

      const result = await verifyApiKey(apiKey);
      expect(result!.lastUsedAt).not.toBeNull();
      expect(result!.lastUsedAt).toBeGreaterThan(0);

      const stored = await getApiKey(hash);
      expect(stored!.lastUsedAt).toBeGreaterThan(0);
    });

    it("accepts a key whose stored enabled field is the boolean true (upstash deserialization)", async () => {
      const { apiKey, metadata } = await createApiKey("bool-verify", "pro");
      const hash = hashApiKey(apiKey);
      mockedRedis.hgetall.mockResolvedValueOnce({
        name: "bool-verify",
        prefix: metadata.prefix,
        tier: "pro",
        enabled: true,
        createdAt: metadata.createdAt,
        lastUsedAt: "",
      });

      const result = await verifyApiKey(apiKey);
      expect(result).not.toBeNull();
      expect(result!.enabled).toBe(true);
    });
  });
});
