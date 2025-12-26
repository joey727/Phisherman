import dns from "node:dns/promises";
import { isIP } from "node:net";

// Private and local IP ranges that must be blocked
const PRIVATE_IP_RANGES = [
  /^10\./,
  /^127\./,
  /^172\.(1[6-9]|2[0-9\D]|3[0-1])\./,
  /^192\.168\./,
  /^169\.254\./,
  /^0\./,
];

// Matches IPv6 private, loopback or link-local
const PRIVATE_IPV6 = [
  /^fc00:/, // Unique local
  /^fd00:/,
  /^fe80:/, // Link-local
  /^::1$/, // Loopback
];

// Check if an IP is private
function isPrivateIP(ip: string): boolean {
  if (isIP(ip) === 4) {
    return PRIVATE_IP_RANGES.some((r: RegExp) => r.test(ip));
  }
  if (isIP(ip) === 6) {
    return PRIVATE_IPV6.some((r) => r.test(ip.toLowerCase()));
  }
  return true;
}

export async function safeResolveHost(host: string): Promise<string[]> {
  // If host is already an IP address
  if (isIP(host)) {
    if (isPrivateIP(host)) {
      throw new Error(`Blocked direct IP access to private range: ${host}`);
    }
    return [host];
  }

  // Resolve A & AAAA records
  let ips: string[] = [];
  try {
    const A = await dns.resolve4(host).catch(() => []);
    const AAAA = await dns.resolve6(host).catch(() => []);
    ips = [...A, ...AAAA];
  } catch (e) {
    throw new Error("DNS resolution failed: " + (e as any).message);
  }

  if (ips.length === 0) {
    throw new Error("Host resolved but no valid A/AAAA records found");
  }

  // Block private IPs
  for (const ip of ips) {
    if (isPrivateIP(ip)) {
      throw new Error(`Blocked private IP address: ${ip}`);
    }
  }

  // DNS Rebinding Protection (re-resolve to check consistency)
  const secondLookup = await dns.lookup(host, { all: true }).catch(() => []);
  const reboundIPs = secondLookup.map((r) => r.address);

  for (const ip of reboundIPs) {
    if (isPrivateIP(ip)) {
      throw new Error(`Blocked via DNS rebinding check: ${ip}`);
    }
  }

  return ips;
}

export function blockIfPrivate(host: string) {
  if (isIP(host) && isPrivateIP(host)) {
    throw new Error("Blocked private IP address (SSRF protection)");
  }
}
