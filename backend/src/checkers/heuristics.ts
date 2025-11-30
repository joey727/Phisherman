import { URL } from "node:url";
import { parse } from "tldts";
import { safeResolveHost, blockIfPrivate } from "../utils/network";

export async function heuristicCheck(url: string) {
  let score = 0;
  const reasons: string[] = [];

  let parsed = new URL(url.startsWith("http") ? url : `http://${url}`);

  const hostname = parsed.hostname;
  blockIfPrivate(hostname);

  const domainInfo = parse(hostname);
  const domain = domainInfo.domain || hostname;
  

  // Length
  if (url.length > 200) {
    score += 10;
    reasons.push("URL very long");
  }

  // '@' sign
  if (url.includes("@")) {
    score += 20;
    reasons.push("Contains '@' (phishing trick)");
  }

  // Suspicious tokens
  const sus = ["verify", "update", "secure", "login", "support", "account"];
  const count = sus.filter(x => url.toLowerCase().includes(x)).length;
  if (count > 0) {
    score += count * 7;
    reasons.push("Contains suspicious keywords");
  }

  // Domain hyphens
  if (domain.includes("-")) {
    score += 6;
    reasons.push("Hyphens in domain");
  }

  // HTTPS check
  if (parsed.protocol !== "https:") {
    score += 10;
    reasons.push("URL is not HTTPS");
  }

  // DNS resolution
  try {
    await safeResolveHost(hostname);
  } catch {
    score += 25;
    reasons.push("DNS failed or private network");
  }

  return { score, reason: reasons.join("; ") };
}
