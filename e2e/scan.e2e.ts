// whois-json is a pure-ESM package (-> `whois` -> `import net from "net"`), which
// Jest's CJS loader cannot resolve. Mock only that library at its network boundary
// (port-43 WHOIS lookup) so the rest of the real pipeline stays real + deterministic.
jest.mock("whois-json", () => jest.fn().mockResolvedValue({}));

import request from "supertest";
import { createApp } from "../src/app";
import { analyzeUrl } from "../src/Scanner";
import redis from "../src/utils/redis";

// Boots the REAL app, Scanner, registry, and checkers — no mocks.
// Exercises: backpressure -> apiLimiter -> validation -> analyzeUrl ->
//   Redis result cache -> URL parse -> all 8 checkers -> scoring -> verdict -> response.
// Requires live Upstash Redis (from .env) and network access.

const app = createApp();

function expectedVerdict(score: number): string {
  return score >= 70 ? "phishing" : score >= 40 ? "suspicious" : "safe";
}

async function flushState() {
  try {
    await redis.del("scan_results");
    await redis.del("scan_results_expiry");
    await redis.del("whois_data");
    await redis.del("whois_expiry");
    await redis.del("scan_log");
    // Clear ratelimit counters for the ephemeral test IPs
    const keys = await redis.keys("ratelimit:*");
    if (keys && keys.length) {
      await Promise.all(keys.map((k: string) => redis.del(k)));
    }
  } catch (err) {
    // If Redis is unreachable, real scanning will still fail-open; log but continue.
    console.error("e2e flushState error:", err);
  }
}

describe("End-to-end URL scanning", () => {
  beforeAll(async () => {
    await flushState();
  });

  afterAll(async () => {
    await flushState();
  });

  it("returns health status", async () => {
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: "ok" });
  });

  it("returns metrics", async () => {
    const res = await request(app).get("/metrics");
    expect(res.status).toBe(200);
    for (const k of ["feedUrls", "processed", "enqueued", "queueLen", "inFlight"]) {
      expect(typeof res.body[k]).toBe("number");
    }
  });

  it("validates missing and non-string URLs", async () => {
    const missing = await request(app).post("/api/check").send({});
    expect(missing.status).toBe(400);
    expect(missing.body.error).toMatch(/Missing 'url'/);

    const blank = await request(app).post("/api/check").send({ url: "" });
    expect(blank.status).toBe(400);
    expect(blank.body.error).toMatch(/Missing 'url'/);
  });

  const SCAN_CASES: Array<{ name: string; url: string; expect?: (r: any) => void }> = [
    {
      name: "safe site scans as safe",
      url: "https://example.com",
      expect: (r) => {
        expect(r.verdict).toBe("safe");
        expect(r.score).toBeLessThanOrEqual(40);
      },
    },
    {
      name: "phishy URL is flagged",
      url: "https://login-secure-verify.example.com/update/account",
      expect: (r) => {
        expect(r.score).toBeGreaterThanOrEqual(40);
        expect(r.reasons).toEqual(expect.arrayContaining(["Contains suspicious keywords"]));
      },
    },
    {
      name: "URL shortener is flagged",
      url: "https://bit.ly/xyz123",
      expect: (r) => {
        expect(r.reasons).toEqual(expect.arrayContaining(["URL shortener used"]));
      },
    },
    {
      name: "credential-style '@' URL is flagged",
      url: "https://login.example.com@evil.example.net/?redirect=1",
      expect: (r) => {
        expect(r.score).toBeGreaterThanOrEqual(40);
        expect(r.reasons).toEqual(expect.arrayContaining(["Contains '@' (phishing trick)"]));
      },
    },
    {
      name: "private IP is blocked",
      url: "http://10.0.0.1/",
      expect: (r) => {
        expect(r.score).toBeGreaterThanOrEqual(40);
        expect(r.reasons).toEqual(
          expect.arrayContaining(["Private/Internal network address"]),
        );
      },
    },
  ];

  for (const c of SCAN_CASES) {
    it(`scans: ${c.name}`, async () => {
      let res: any;
      // Real-network scans can hit the 2.5s checker watchdog (slow DNS) transiently;
      // retry such watchdog timeouts once so the suite isn't flaky.
      for (let attempt = 0; attempt < 2; attempt++) {
        res = await request(app).post("/api/check").send({ url: c.url });
        if (
          res.status !== 200 ||
          (res.body.reasons as string[]).join(" ").includes("timed out")
        ) {
          continue;
        }
        break;
      }
      expect(res!.status).toBe(200);
      expect(res!.body.verdict).toBe(expectedVerdict(res!.body.score));
      expect(typeof res!.body.score).toBe("number");
      expect(Array.isArray(res!.body.reasons)).toBe(true);
      expect(res!.body.executionTimeMs).toBeDefined();
      c.expect?.(res!.body);
    });
  }

  it("exercises the ML checker without crashing (fallback or remote)", async () => {
    const res = await request(app)
      .post("/api/check")
      .send({ url: "https://verify-secure-login.example.net/account" });
    expect(res.status).toBe(200);
    expect(typeof res.body.score).toBe("number");
    expect(res.body.reasons).toBeInstanceOf(Array);
  });

  it("runs real ML inference when ML_SERVICE_URL is reachable", async () => {
    const mlUrl = process.env.ML_SERVICE_URL;
    if (!mlUrl) {
      // eslint-disable-next-line no-console
      console.log("ML_SERVICE_URL not set — skipping remote inference assertion");
      return;
    }

    // Verify the configured endpoint is actually up before asserting on its output.
    let up = false;
    try {
      const h = await fetch(`${mlUrl}/health`);
      up = h.ok && (await h.json()).model_loaded === true;
    } catch {
      up = false;
    }
    if (!up) {
      // eslint-disable-next-line no-console
      console.log(`ML service at ${mlUrl} not reachable — skipping remote inference assertion`);
      return;
    }

    // Unique URL + flush so we always exercise a fresh, uncached inference run.
    const scanUrl = `https://verify-secure-login.example.net/account?e2e=${Date.now()}`;
    await flushState();

    const res = await request(app).post("/api/check").send({ url: scanUrl });
    expect(res.status).toBe(200);
    const reasons = res.body.reasons as string[];
    // Feature-explainability lines are prefixed "ML: ", while the model label line is "ML model: ",
    // so filter on the "ML" prefix (a space, not a colon) to capture both.
    const mlReasons = reasons.filter((r) => r.startsWith("ML"));
    expect(mlReasons.length).toBeGreaterThan(0);
    expect(reasons.some((r) => r.startsWith("ML model:"))).toBe(true);
  });

  it("records scanned URLs to the feedback log when enabled", async () => {
    await flushState();
    const url = `https://example.com/feedback-${Date.now()}`;
    const res = await request(app).post("/api/check").send({ url });
    expect(res.status).toBe(200);
    const members = await redis.zrange("scan_log", 0, -1);
    expect(members).toContain(url);
  });

  it("returns the expected envelope for the analyzeUrl result", async () => {
    const result = await analyzeUrl("https://example.com");
    expect(result).toMatchObject({
      url: "https://example.com",
      score: expect.any(Number),
      verdict: expect.any(String),
      reasons: expect.any(Array),
      executionTimeMs: expect.any(Object),
    });
    expect(Array.from(Object.keys(result.executionTimeMs || {})).length).toBeGreaterThan(0);
  });
});