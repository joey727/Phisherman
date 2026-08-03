import { ingestUrls } from "../src/feeds/ingest";
import redis from "../src/utils/redis";

jest.mock("../src/utils/redis", () => ({
  sadd: jest.fn(),
  get: jest.fn(),
  set: jest.fn(),
  rename: jest.fn(),
  execute: jest.fn(),
}));

describe("ingestUrls", () => {
  const mockedRedis = redis as unknown as jest.Mocked<any>;

  beforeEach(() => jest.clearAllMocks());

  it("adds URLs to redis set and persists bloom", async () => {
    mockedRedis.get.mockResolvedValue(null);
    mockedRedis.sadd.mockResolvedValue(2);
    mockedRedis.set.mockResolvedValue("OK");

    const urls = ["http://a.test/1", "http://b.test/2"];
    await ingestUrls("test_key", urls, { batchSize: 2 });

    expect(mockedRedis.sadd).toHaveBeenCalled();
    expect(mockedRedis.set).toHaveBeenCalled();
  });
});
