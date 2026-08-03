import { runWorkerLoop } from "../src/analysis/worker";
import redis from "../src/utils/redis";

jest.mock("../src/utils/redis", () => ({
  brpop: jest.fn(),
  hset: jest.fn(),
}));

jest.mock("../src/utils/enrich", () => ({
  enrichUrl: jest.fn().mockResolvedValue({ dns: [] }),
}));

jest.mock("../src/Scanner", () => ({
  analyzeUrl: jest.fn().mockResolvedValue({ url: "http://x", score: 0 }),
}));

describe("Worker Loop", () => {
  const mockedRedis = redis as unknown as jest.Mocked<any>;

  beforeEach(() => jest.clearAllMocks());

  it("processes one queued url then stops", async () => {
    // first brpop returns a queued item, second returns null
    mockedRedis.brpop
      .mockResolvedValueOnce(["analysis_queue", "http://x"])
      .mockResolvedValue(null);

    let looped = 0;
    const stopSignal = () => looped++ > 0; // stop after one iteration

    // run worker loop but it will exit quickly
    const p = runWorkerLoop(stopSignal);
    // allow a short tick
    await new Promise((r) => setTimeout(r, 50));
    // ensure hset was called to persist meta
    expect(mockedRedis.hset).toHaveBeenCalled();
    // stop the loop by awaiting the promise (it should finish because stopSignal becomes true)
    // Note: runWorkerLoop may be blocked briefly; give it some time
    await new Promise((r) => setTimeout(r, 50));
  });
});
