import dns from "node:dns/promises";
import { isIP } from "node:net";

const PRIVATE_IP_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,
  /^0\./,
];



export async function safeResolveHost(host: string): Promise<string[]> {
  const addrs = await dns.lookup(host, { all: true });

  const ips = addrs.map(a => a.address);

  for (const ip of ips) {
    if (PRIVATE_IP_RANGES.some(r => r.test(ip))) {
      throw new Error(`Blocked private IP address: ${ip}`);
    }
  }

  return ips;
}

export function blockIfPrivate(host: string) {
  if (isIP(host)) {
    if (PRIVATE_IP_RANGES.some(r => r.test(host))) {
      throw new Error("Private IP blocked (SSRF protection)");
    }
  }
}
