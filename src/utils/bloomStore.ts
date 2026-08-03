import redis from "./redis";
import { BloomFilter } from "./bloom";

const USE_REDIS_BLOOM =
  (process.env.USE_REDIS_BLOOM || "false").toLowerCase() === "true";

export class BloomStore {
  private local: BloomFilter | null = null;
  private readonly redisKey: string;

  constructor(redisKey: string) {
    this.redisKey = redisKey;
  }

  async init() {
    if (USE_REDIS_BLOOM) {
      // Try to detect BF.EXISTS support by issuing a harmless command
      if (typeof (redis as any).execute === "function") {
        try {
          // noop reserve check: skip creating if exists
          await (redis as any).execute(["PING"]);
          return;
        } catch {
          // fall through to local
        }
      }
    }

    // Load serialized local bloom from redis if present
    try {
      const b64 = await redis.get(this.redisKey);
      if (b64) {
        this.local = BloomFilter.deserialize(b64 as string);
      } else {
        this.local = new BloomFilter();
      }
    } catch (err) {
      this.local = new BloomFilter();
    }
  }

  has(item: string): boolean | Promise<boolean> {
    if (USE_REDIS_BLOOM) {
      // attempt RedisBloom BF.EXISTS
      try {
        if (typeof (redis as any).execute === "function") {
          return (async () => {
            try {
              const res = await (redis as any).execute([
                "BF.EXISTS",
                this.redisKey,
                item,
              ]);
              return Number(res) === 1 || res === 1 || res === true;
            } catch {
              // fallback to local
              return this.local ? this.local.has(item) : false;
            }
          })();
        }
      } catch {
        // fallback
      }
    }

    return this.local ? this.local.has(item) : false;
  }

  async addBatch(items: string[]) {
    if (USE_REDIS_BLOOM) {
      if (typeof (redis as any).execute === "function") {
        try {
          // Use BF.MADD if available
          const args = ["BF.MADD", this.redisKey, ...items];
          await (redis as any).execute(args);
          return;
        } catch (err) {
          // fallback to local
        }
      }
    }

    if (!this.local) this.local = new BloomFilter();
    for (const it of items) this.local.add(it);
  }

  async persist() {
    if (USE_REDIS_BLOOM) return; // RedisBloom stores data server-side
    if (!this.local) return;
    try {
      await redis.set(this.redisKey, this.local.serialize());
    } catch (err) {
      // ignore
    }
  }
}

export async function getBloomStore(key: string) {
  const s = new BloomStore(key);
  await s.init();
  return s;
}
