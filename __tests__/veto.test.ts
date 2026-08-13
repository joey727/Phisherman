import { HeuristicsChecker } from "../src/checkers/heuristics";
import redis from "../src/utils/redis";

jest.mock("../src/utils/redis", () => {
  const store = new Map<string, any>();
  const mock = {
    get: jest.fn(async (key: string) => store.get(key)),
    set: jest.fn(async (key: string, value: any) => store.set(key, value)),
    hget: jest.fn(async (key: string, field: string) => {
      const h = store.get(key) || {};
      return h[field];
    }),
    hset: jest.fn(async (key: string, data: any) => {
      const h = store.get(key) || {};
      Object.assign(h, data);
      store.set(key, h);
    }),
    zadd: jest.fn(async () => {}),
    zrange: jest.fn(async () => []),
    hdel: jest.fn(async () => {}),
    zrem: jest.fn(async () => {}),
    pipeline: jest.fn(() => ({
      hset: jest.fn().mockReturnThis(),
      zadd: jest.fn().mockReturnThis(),
      hdel: jest.fn().mockReturnThis(),
      zrem: jest.fn().mockReturnThis(),
      exec: jest.fn(async () => [1, 1]),
    })),
  };
  mock.__reset = () => store.clear();
  return mock;
});

jest.mock("../src/utils/network", () => ({
  safeResolveHost: jest.fn(async () => ["1.2.3.4"]),
  blockIfPrivate: jest.fn(),
}));

let whoisCreated: string | null = "2000-01-01";
let rdapMock: jest.Mock;
jest.mock("whois-json", () => {
  return jest.fn(async () =>
    whoisCreated === null
      ? {}
      : { createdDate: whoisCreated, registrar: "Fake Registrar" },
  );
});

const realFetch = global.fetch;
beforeAll(() => {
  rdapMock = jest.fn();
  global.fetch = rdapMock as unknown as typeof fetch;
});
afterAll(() => {
  global.fetch = realFetch;
});

// The full guarded set from the pipeline's BENCHMARK_GUARDED_BENIGN:
// doc/dev/news sites + long-tail niche brands. Every one must be rescued by the
// established-domain veto (whois age >= 365d + lexically clean).
const GUARDED_URLS = [
  // Doc/dev/news sites
  "https://docs.python.org/library/",
  "https://www.python.org/",
  "https://www.postgresql.org/",
  "https://postgresql.org/docs/",
  "https://www.gnu.org/",
  "https://nodejs.org/en",
  "https://getbootstrap.com/",
  "https://webpack.js.org/",
  "https://www.archlinux.org/",
  "https://reactjs.org/docs/",
  "https://www.docker.com/",
  "https://docs.docker.com/get-started/",
  "https://kubernetes.io/",
  "https://archive.org/details/",
  "https://www.w3.org/TR/html/",
  "https://news.ycombinator.com/",
  "https://www.anthropic.com/",
  // Long-tail niche brands
  "https://www.miele.com/",
  "https://www.leica-camera.com/",
  "https://www.napaonline.com/",
  "https://www.goodyear.com/",
  "https://www.hollisterco.com/",
  "https://www.quizlet.com/",
  "https://firehydrant.io/",
  "https://oncall.tools/",
];

describe("Established-domain veto", () => {
  beforeEach(() => {
    (redis as unknown as { __reset: () => void }).__reset();
    whoisCreated = "2000-01-01";
    rdapMock.mockReset();
  });

  test("fires for every guarded legit URL (age >= 365d + lexically clean)", async () => {
    for (const url of GUARDED_URLS) {
      const result = await HeuristicsChecker.check(url);
      expect(result.veto).toBe(true);
    }
  });

  test("falls back to RDAP when whois yields no creation date", async () => {
    whoisCreated = null; // whois-json returns empty object
    rdapMock.mockResolvedValue({
      ok: true,
      json: async () => ({
        events: [{ eventAction: "registration", eventDate: "1998-11-30" }],
      }),
    });
    const result = await HeuristicsChecker.check("https://www.goodyear.com/");
    expect(rdapMock).toHaveBeenCalledWith(
      expect.stringContaining("rdap.org/domain/goodyear.com"),
      expect.anything(),
    );
    expect(result.veto).toBe(true);
  });

  test("does not fire when both whois and RDAP fail", async () => {
    whoisCreated = null;
    rdapMock.mockResolvedValue({ ok: false });
    const result = await HeuristicsChecker.check("https://oncall.tools/");
    expect(result.veto).toBe(false);
  });

  test("does not fire for a freshly registered domain", async () => {
    whoisCreated = "2026-01-01";
    const result = await HeuristicsChecker.check("https://www.miele.com/");
    expect(result.veto).toBe(false);
  });

  test("does not fire for a suspicious-keyword URL even on an old domain", async () => {
    whoisCreated = "2000-01-01";
    const result = await HeuristicsChecker.check(
      "https://www.miele.com/verify/account",
    );
    expect(result.veto).toBe(false);
  });

  test("does not fire for brand impersonation on an old domain", async () => {
    whoisCreated = "2000-01-01";
    const result = await HeuristicsChecker.check(
      "https://secure-paypal-verify.com/login",
    );
    expect(result.veto).toBe(false);
  });

  test("does not fire for a non-HTTPS URL", async () => {
    whoisCreated = "2000-01-01";
    const result = await HeuristicsChecker.check("http://www.miele.com/");
    expect(result.veto).toBe(false);
  });

  test("does not fire for a suspicious TLD even on an old-looking domain", async () => {
    whoisCreated = "2000-01-01";
    const result = await HeuristicsChecker.check("https://www.miele.tk/");
    expect(result.veto).toBe(false);
  });
});