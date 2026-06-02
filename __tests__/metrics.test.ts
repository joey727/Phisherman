import { incMetric, getMetric } from "../src/utils/metrics";
import redis from "../src/utils/redis";

jest.mock("../src/utils/redis", () => ({
  incrby: jest.fn(),
  get: jest.fn(),
}));

describe("metrics helpers", () => {
  const mocked = redis as unknown as jest.Mocked<any>;
  beforeEach(() => jest.clearAllMocks());

  it("incMetric calls redis.incrby", async () => {
    mocked.incrby.mockResolvedValue(5);
    await incMetric("test_metric", 2);
    expect(mocked.incrby).toHaveBeenCalledWith("metrics:test_metric", 2);
  });

  it("getMetric returns number from redis.get", async () => {
    mocked.get.mockResolvedValue("7");
    const v = await getMetric("test_metric");
    expect(v).toBe(7);
  });
});
