import dns from "node:dns";
import { promisify } from "util";
import whois from "whois-json";
import tldts from "tldts";

const resolve = promisify(dns.resolveAny);

export async function enrichUrl(url: string) {
  const parsed = tldts.parse(url);
  const hostname =
    parsed.domain || parsed.hostname || parsed.publicSuffix || parsed.hostname;
  const result: any = { hostname };
  try {
    if (hostname) {
      const records = await resolve(hostname).catch(() => null);
      result.dns = records;
    }
  } catch (err) {
    result.dnsError = String(err);
  }

  try {
    if (hostname) {
      const w = await whois(hostname);
      result.whois = w;
    }
  } catch (err) {
    result.whoisError = String(err);
  }

  return result;
}
