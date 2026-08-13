import { URL } from "node:url";
import { parse } from "tldts";
import { safeResolveHost, blockIfPrivate } from "../utils/network";
import whois from "whois-json";
import redis from "../utils/redis";
import { Checker, CheckResult, ParsedUrl } from "../types";

const WHOIS_CACHE_TTL = 86400 * 1000; // 24 hours in ms
const KEY_WHOIS_DATA = "whois_data";
const KEY_WHOIS_EXPIRY = "whois_expiry";
const KEY_RDAP_DATA = "rdap_data";
const KEY_RDAP_EXPIRY = "rdap_expiry";
// RDAP is only attempted when the URL could qualify for the veto and the whois
// lookup failed. The combined budget across both bases must fit inside the
// heuristics checker's deadline (CheckerRegistry.TIMEOUT_MS = 2500) alongside
// DNS + whois, otherwise the whole checker times out and loses its signal.
const RDAP_TOTAL_MS = 2000;

// ---------------------------------------------------------------------------
// Established-domain veto
//
// A domain is treated as established-and-benign when it has been registered for
// >= 365 days (from whois, with an RDAP fallback) AND the URL is lexically
// clean. The reputation signal (age) lives in this rule layer instead of as an
// ML feature, so the classifier can stay purely lexical and no popularity list
// / RDAP crawl is needed. This covers ALL established legitimate domains,
// including long-tail brands the model has never seen (miele.com,
// leica-camera.com, ...).
//
// The lists below are duplicated from ml-service/app/features.py, which is the
// authoritative source. Keep them in sync: the pipeline's long-tail promotion
// gate and the heuristics veto Jest test both guard against drift.
// ---------------------------------------------------------------------------

const SUSPICIOUS_TLDS = new Set([
  "tk", "ml", "cf", "ga", "gq", "top", "xyz", "buzz", "club", "online",
  "site", "icu", "work", "info", "su", "pw", "cc", "ws",
]);

const BRAND_KEYWORDS = [
  "paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
  "instagram", "whatsapp", "chase", "wellsfargo", "bankofamerica", "citi",
  "usps", "dhl", "fedex", "ups", "dropbox", "linkedin", "twitter", "ebay",
  "yahoo", "outlook", "office365", "icloud", "coinbase", "binance",
];

const SUSPICIOUS_KEYWORDS = [
  "verify", "update", "secure", "login", "support", "account", "confirm",
  "suspend", "alert", "urgent", "expire", "unlock", "validate", "password",
  "credential", "signin", "billing", "invoice", "refund", "reward",
];

const SHORTENER_DOMAINS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "lnkd.in", "rb.gy",
];

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function hasWordBoundary(haystack: string, needle: string): boolean {
  return new RegExp(`\\b${escapeRegExp(needle)}\\b`).test(haystack);
}

// whois-json uses raw TCP sockets and is unreliable for some registries
// (Verisign timeouts, .tools routing to IANA, empty results). RDAP is a
// structured HTTPS fallback used ONLY when whois yields no creation date.
// rdap.org covers most TLDs; Identity Digital serves TLDs missing from the
// IANA bootstrap (e.g. .io), so it is tried second.
const RDAP_BASES = [
  "https://rdap.org/domain/",
  "https://rdap.identitydigital.services/rdap/domain/",
];
const RDAP_INPROC_NULL_TTL = 15 * 60 * 1000;

// in-process negative cache only lasts 15 minutes so a transient RDAP failure
// does not block a domain for hours; successful dates live as long as whois.
const rdapCache = new Map<string, { date: string | null; ts: number }>();

async function fetchRdapDate(domain: string): Promise<string | null> {
  const deadline = Date.now() + RDAP_TOTAL_MS;
  for (const base of RDAP_BASES) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) break;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), remaining);
      try {
        const resp = await fetch(base + encodeURIComponent(domain), {
          signal: controller.signal,
          redirect: "follow",
          headers: { accept: "application/rdap+json" },
        });
        if (resp.ok) {
          const data: any = await resp.json();
          const events: Array<{ eventAction?: string; eventDate?: string }> =
            data?.events ?? [];
          const registration = events.find(
            (e) => e.eventAction === "registration",
          );
          const date = registration?.eventDate ?? null;
          if (date) return date;
        }
      } finally {
        clearTimeout(timer);
      }
    } catch {
      /* try the next base */
    }
  }
  return null;
}

async function rdapCreationDate(domain: string): Promise<string | null> {
  const now = Date.now();
  const cached = rdapCache.get(domain);
  if (cached) {
    const ttl = cached.date ? WHOIS_CACHE_TTL : RDAP_INPROC_NULL_TTL;
    if (now - cached.ts < ttl) return cached.date;
  }

  try {
    const raw = await redis.hget(KEY_RDAP_DATA, domain);
    if (raw) {
      const parsed = JSON.parse(raw as string);
      const date = parsed?.date ?? null;
      // Only non-null dates are trusted from Redis; transient failures must
      // not poison the cache for 24 hours.
      if (date) {
        rdapCache.set(domain, { date, ts: now });
        return date;
      }
    }
  } catch {
    /* redis unavailable -- fall through to live lookup */
  }

  const date = await fetchRdapDate(domain);

  if (date) {
    try {
      await redis.hset(KEY_RDAP_DATA, { [domain]: JSON.stringify({ date }) });
      await redis.zadd(KEY_RDAP_EXPIRY, {
        score: Date.now() + WHOIS_CACHE_TTL,
        member: domain,
      });
    } catch {
      /* cache write failures are non-fatal */
    }
  }
  rdapCache.set(domain, { date, ts: Date.now() });
  return date;
}

async function whoisCheck(
  regDomain: string,
  hostname: string,
  opts?: { skipRdap?: boolean },
) {
  const reasons: string[] = [];
  const details: Record<string, any> = {};
  let scoreDelta = 0;

  const lookupKey = regDomain || hostname;

  let whoisInfo: any;
  try {
    // Try cache first (Hash)
    const cached = await redis.hget(KEY_WHOIS_DATA, lookupKey);

    if (cached) {
      whoisInfo = JSON.parse(cached as string);
    } else {
      // Wrap whois in a timeout -- the library uses raw TCP sockets with no built-in
      // timeout. whois is the flaky source, so keep it short and let RDAP (the
      // reliable HTTPS source) serve as the fallback for veto-eligible URLs.
      const WHOIS_TIMEOUT_MS = 300;
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        const whoisRaw = await Promise.race([
          whois(lookupKey),
          new Promise<never>((_, reject) => {
            timer = setTimeout(() => reject(new Error("WHOIS lookup timed out")), WHOIS_TIMEOUT_MS);
          }),
        ]) as any;

        whoisInfo = Array.isArray(whoisRaw)
          ? whoisRaw[0] || {}
          : whoisRaw || {};

        // Cache the result (Hash + ZSET)
        const now = Date.now();
        await redis.hset(KEY_WHOIS_DATA, { [lookupKey]: JSON.stringify(whoisInfo) });
        await redis.zadd(KEY_WHOIS_EXPIRY, { score: now + WHOIS_CACHE_TTL, member: lookupKey });
      } finally {
        if (timer) clearTimeout(timer);
      }
    }
  } catch (err) {
    details.whoisError = String(err);
  }

  details.whois = {
    registrar: whoisInfo?.registrar || whoisInfo?.["Registrar"],
    creationDate:
      whoisInfo?.creationDate ||
      whoisInfo?.createdDate ||
      whoisInfo?.["Creation Date"],
    updatedDate: whoisInfo?.updatedDate || whoisInfo?.updated,
    raw: undefined,
  };

  let creationDate: string | null = details.whois.creationDate ?? null;
  if (!creationDate && !opts?.skipRdap) {
    // whois failed to yield a creation date -- fall back to RDAP (cached)
    creationDate = await rdapCreationDate(lookupKey);
    if (creationDate) {
      details.whois.creationDate = creationDate;
      details.whois.source = "rdap";
    }
  }

  const cd = creationDate ? new Date(creationDate) : null;
  if (cd && !isNaN(cd.getTime())) {
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

  return { scoreDelta, reasons, details };
}

export async function heuristicCheck(url: string, parsed?: ParsedUrl): Promise<CheckResult> {
  let score = 0;
  const reasons: string[] = [];

  // Use pre-parsed URL if available, otherwise parse locally
  let hostname: string;
  let protocol: string;
  if (parsed) {
    hostname = parsed.hostname;
    protocol = parsed.protocol;
  } else {
    try {
      const u = new URL(url.startsWith("http") ? url : `http://${url}`);
      hostname = u.hostname;
      protocol = u.protocol;
    } catch {
      return { score: 0 };
    }
  }

  try {
    blockIfPrivate(hostname);
  } catch {
    return { score: 50, reasons: ["Private/Internal network address"] };
  }

  const domainInfo = parse(hostname);
  const domain = domainInfo.domain || hostname;

  // Data URI check
  if (url.toLowerCase().startsWith("data:text/html")) {
    score += 40;
    reasons.push("Data URI (common evasion technique)");
  }

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

  // Punycode & IDN homograph attack check
  if (hostname.includes("xn--")) {
    score += 20;
    reasons.push("Punycode/IDN domain (possible homograph attack)");
  } else if (/[^a-zA-Z0-9.\-_]/.test(hostname)) {
    score += 15;
    reasons.push("Suspicious characters in hostname");
  }

  // URL shorteners
  const shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly"];
  if (shorteners.some(s => hostname.endsWith(s))) {
    score += 10;
    reasons.push("URL shortener used");
  }

  // Subdomain depth
  const parts = hostname.split(".");
  if (parts.length > 4) {
    score += 10;
    reasons.push("Excessive subdomain depth");
  }

  // HTTPS check
  if (protocol !== "https:") {
    score += 10;
    reasons.push("URL is not HTTPS");
  }

  // DNS resolution
  let dnsResolved = false;
  try {
    await safeResolveHost(hostname);
    dnsResolved = true;
  } catch {
    score += 25;
    reasons.push("DNS failed or private network");
  }

  // Established-domain veto preconditions that need no network. If any fail the
  // veto cannot fire, so the whois/RDAP age lookup (the slowest part) is only
  // attempted when the URL could still qualify -- otherwise a fresh phish domain
  // would burn the RDAP budget and time the whole checker out.
  const urlLower = url.toLowerCase();
  const apex = domainInfo.domain || "";
  const vetoEligible =
    dnsResolved &&
    protocol === "https:" &&
    !(domainInfo.publicSuffix && SUSPICIOUS_TLDS.has(domainInfo.publicSuffix)) &&
    !hostname.includes("xn--") &&
    !url.includes("@") &&
    !urlLower.startsWith("data:text/html") &&
    !SHORTENER_DOMAINS.some((s) => hostname.endsWith(s)) &&
    parts.length <= 4 &&
    !BRAND_KEYWORDS.some((b) => b !== apex && hasWordBoundary(urlLower, b)) &&
    !SUSPICIOUS_KEYWORDS.some((k) => hasWordBoundary(urlLower, k));

  // whois lookup
  const whoisResult = await whoisCheck(domain, hostname, {
    skipRdap: !vetoEligible,
  });
  score += whoisResult.scoreDelta;
  reasons.push(...whoisResult.reasons);

  score = Math.max(0, score);

  // Established-domain veto: an old registered domain + a lexically clean URL is
  // a safe-looking URL regardless of what the lexical ML model thinks. Attackers
  // register fresh domains, so the age rule already excludes their URLS; feed
  // checkers (URLHaus, PhishTank, SafeBrowsing, VT) still run and can override.
  const ageDays = whoisResult.details.domainAgeDays;
  const veto = typeof ageDays === "number" && ageDays >= 365 && vetoEligible;

  return { score, reasons, veto };
}

export const HeuristicsChecker: Checker = {
  name: "heuristics",
  check: heuristicCheck,
};

