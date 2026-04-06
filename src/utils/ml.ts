import tldts from "tldts";
import crypto from "node:crypto";

function hostnameEntropy(hostname: string) {
  const s = hostname.replace(/\./g, "");
  const freqs: Record<string, number> = {};
  for (const c of s) freqs[c] = (freqs[c] || 0) + 1;
  const probs = Object.values(freqs).map((v) => v / s.length);
  const H = -probs.reduce((a, p) => a + (p > 0 ? p * Math.log2(p) : 0), 0);
  return H;
}

export async function scoreUrlMl(
  url: string,
  meta: any = {},
): Promise<{ score: number; reasons: string[] }> {
  const reasons: string[] = [];
  let score = 0;

  try {
    const parsed = tldts.parse(url);
    const hostname = parsed.hostname || "";

    // entropy: suspicious if very low or very high randomness
    const ent = hostnameEntropy(hostname || "");
    if (ent > 4.5) {
      score += 12;
      reasons.push("High hostname entropy");
    }

    // too many digits
    const digitCount = (hostname.match(/\d/g) || []).length;
    if (digitCount > 3) {
      score += 8;
      reasons.push("Many digits in hostname");
    }

    // long path
    if (url.length > 180) {
      score += 6;
      reasons.push("Long URL");
    }

    // suspicious tld
    const suspectTlds = ["tk", "ml", "cf", "ga"];
    if (suspectTlds.includes(parsed.publicSuffix || "")) {
      score += 8;
      reasons.push("Suspicious TLD");
    }

    // whois age if present in meta
    const age =
      meta?.result?.meta?.whois?.domainAgeDays ||
      meta?.meta?.domainAgeDays ||
      meta?.whois?.domainAgeDays;
    if (typeof age === "number") {
      if (age < 30) {
        score += 12;
        reasons.push("Very new domain");
      } else if (age < 180) {
        score += 6;
        reasons.push("Recently created domain");
      }
    }

    // heuristic signals from prior analysis
    const priorScore = meta?.result?.score || 0;
    if (priorScore >= 40) {
      score += Math.min(30, priorScore / 2);
      reasons.push("Existing checkers flagged URL");
    }
  } catch (err) {
    // fail-open: don't crash
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, reasons };
}
