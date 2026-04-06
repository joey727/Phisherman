import redis from "./redis";

export async function incMetric(name: string, by: number = 1) {
  try {
    await redis.incrby(`metrics:${name}`, by);
  } catch (err) {
    // don't fail main flow on metrics error
  }
}

export async function getMetric(name: string) {
  try {
    const v = await redis.get(`metrics:${name}`);
    return Number(v) || 0;
  } catch (err) {
    return 0;
  }
}
