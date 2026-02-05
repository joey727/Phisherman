import { URL } from "node:url";
import { parse } from "tldts";
import { safeResolveHost, blockIfPrivate } from "../utils/network";
import whois from "whois-json";
import redis from "../utils/redis";
import { Checker, CheckResult } from "../types";

const WHOIS_CACHE_TTL = 86400 * 1000; // 24 hours in ms
const KEY_WHOIS_DATA = "whois_data";
const KEY_WHOIS_EXPIRY = "whois_expiry";

async function whoisCheck(regDomain: string, hostname: string) {
  const reasons: string[] = [];
  const details: Record<string, any> = {};
  let scoreDelta = 0;

  const lookupKey = regDomain || hostname;

  try {
    // Try cache first (Hash)
    const cached = await redis.hget(KEY_WHOIS_DATA, lookupKey);
    let whoisInfo: any;

    if (cached) {
      whoisInfo = JSON.parse(cached as string);
    } else {
      const whoisRaw = (await whois(lookupKey)) as any;
      whoisInfo = Array.isArray(whoisRaw)
        ? whoisRaw[0] || {}
        : whoisRaw || {};

      // Cache the result (Hash + ZSET)
      const now = Date.now();
      await redis.hset(KEY_WHOIS_DATA, { [lookupKey]: JSON.stringify(whoisInfo) });
      await redis.zadd(KEY_WHOIS_EXPIRY, { score: now + WHOIS_CACHE_TTL, member: lookupKey });
    }

    details.whois = {
      registrar: whoisInfo.registrar || whoisInfo["Registrar"],
      creationDate:
        whoisInfo.creationDate ||
        whoisInfo.createdDate ||
        whoisInfo["Creation Date"],
      updatedDate: whoisInfo.updatedDate || whoisInfo.updated,
      raw: undefined,
    };

    const cd = details.whois.creationDate
      ? new Date(details.whois.creationDate)
      : null;
    if (cd) {
      const ageDays = Math.floor(
        (Date.now() - cd.getTime()) / (1000 * 60 * 60 * 24)
      );
      details.domainAgeDays = ageDays;
      if (ageDays < 90) {
        scoreDelta += 10;
        reasons.push("Domain is recently created (<90 days)");
      } else if (ageDays < 365) {
        scoreDelta += 4;
      } else {
        scoreDelta -= 2;
      }
    }
  } catch (err) {
    details.whoisError = String(err);
  }

  return { scoreDelta, reasons, details };
}

export async function heuristicCheck(url: string): Promise<CheckResult> {
  let score = 0;
  const reasons: string[] = [];

  let parsed: URL;
  try {
    parsed = new URL(url.startsWith("http") ? url : `http://${url}`);
  } catch {
    return { score: 0 };
  }

  const hostname = parsed.hostname;
  try {
    blockIfPrivate(hostname);
  } catch {
    return { score: 50, reasons: ["Private/Internal network address"] };
  }

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
  const count = sus.filter((x) => url.toLowerCase().includes(x)).length;
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

  // whois lookup
  const whoisResult = await whoisCheck(domain, hostname);
  score += whoisResult.scoreDelta;
  reasons.push(...whoisResult.reasons);

  score = Math.max(0, score);

  return { score, reasons };
}

export const HeuristicsChecker: Checker = {
  name: "heuristics",
  check: heuristicCheck,
};

