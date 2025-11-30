import express from "express";
import cors from "cors";
import { analyzeUrl } from "./Scanner";

const app = express();
app.use(express.json());
app.use(cors());

// type CheckResult = {
//   url: string;
//   score: number; // 0 safe - 100 phishing
//   verdict: "safe" | "suspicious" | "phishing";
//   reasons: string[];
//   details: Record<string, any>;
// };

// const suspiciousTokens = [
//   "login", "signin", "account", "secure", "update", "verify", "bank", "paypal",
//   "confirm", "ebay", "appleid", "google", "facebook", "wallet"
// ];

// function scoreToVerdict(score: number): "safe"|"suspicious"|"phishing" {
//   if (score < 30) return "safe";
//   if (score < 60) return "suspicious";
//   return "phishing";
// }

// function hostnameSubdomainCount(hostname: string) {
//   // simple count of labels
//   return hostname.split(".").length;
// }

// function containsIp(hostname: string) {
//   // IPv4 or IPv6 naive check
//   return /^[0-9.]+$/.test(hostname) || hostname.includes(":");
// }

// function countSuspiciousTokens(url: string) {
//   const lc = url.toLowerCase();
//   return suspiciousTokens.reduce((acc, tok) => acc + (lc.includes(tok) ? 1 : 0), 0);
// }

// // Helper: normalize and parse URL
// function normalizeAndParse(inputUrl: string): { parsed?: URL; error?: string } {
//   try {
//     const parsed = new URL(inputUrl.startsWith("http") ? inputUrl : `https://${inputUrl}`);
//     return { parsed };
//   } catch (err: any) {
//     return { error: String(err) };
//   }
// }

// // Helper: surface-level checks (IP, length, @, extra //, tokens, subdomains, hyphen, protocol)
// function surfaceChecks(parsed: URL, rawInput: string) {
//   const reasons: string[] = [];
//   const details: Record<string, any> = {};
//   let scoreDelta = 0;

//   const hostname = parsed.hostname;
//   details.hostname = hostname;
//   details.protocol = parsed.protocol;
//   details.pathname = parsed.pathname;

//   if (containsIp(hostname)) {
//     scoreDelta += 40;
//     reasons.push("Hostname is an IP address");
//   }

//   if (rawInput.length > 200) {
//     scoreDelta += 10;
//     reasons.push("URL is unusually long");
//   } else if (rawInput.length > 120) {
//     scoreDelta += 5;
//   }

//   if (rawInput.includes("@")) {
//     scoreDelta += 30;
//     reasons.push("Contains '@' - likely trick URL");
//   }

//   const afterProtocol = parsed.href.slice(parsed.protocol.length + 2);
//   if (afterProtocol.includes("//")) {
//     scoreDelta += 5;
//     reasons.push("Contains extra '//' after protocol");
//   }

//   const suspiciousCount = countSuspiciousTokens(parsed.href);
//   details.suspiciousTokenCount = suspiciousCount;
//   if (suspiciousCount > 0) {
//     scoreDelta += Math.min(25, suspiciousCount * 8);
//     reasons.push(`Contains suspicious keywords (${suspiciousCount})`);
//   }

//   const subCount = hostnameSubdomainCount(hostname);
//   details.subdomainCount = subCount;
//   if (subCount >= 4) {
//     scoreDelta += 10;
//     reasons.push("Many subdomains (possible obfuscation)");
//   }

//   const regDomain = parseDomain(hostname).domain || "";
//   details.regDomain = regDomain;
//   if (regDomain.includes("-")) {
//     scoreDelta += 6;
//     reasons.push("Hyphen in registered domain (common in phishing)");
//   }

//   if (parsed.protocol === "https:") {
//     scoreDelta -= 2;
//   } else {
//     scoreDelta += 12;
//     reasons.push("Not HTTPS");
//   }

//   return { scoreDelta, reasons, details, regDomain };
// }

// // Helper: DNS lookup
// async function dnsCheck(hostname: string) {
//   const reasons: string[] = [];
//   const details: Record<string, any> = {};
//   let scoreDelta = 0;
//   try {
//     const addrs = await dns.lookup(hostname, { all: true });
//     details.dns = addrs.map(a => a.address);
//     if (addrs.length === 0) {
//       scoreDelta += 20;
//       reasons.push("Hostname did not resolve");
//     }
//   } catch (err) {
//     scoreDelta += 20;
//     reasons.push("DNS lookup failed");
//     details.dnsError = String(err);
//   }
//   return { scoreDelta, reasons, details };
// }

// // Helper: fetch redirects (uses got)
// async function redirectCheck(href: string) {
//   const reasons: string[] = [];
//   const details: Record<string, any> = {};
//   let scoreDelta = 0;

//   try {
//     const r = await got(href, {
//       method: "GET",
//       followRedirect: true,
//       timeout: { request: 8000 },
//       retry: { limit: 0 }
//     });
//     const redirects = (r as any).redirectUrls || [];
//     details.redirectCount = redirects.length;
//     if (redirects.length >= 3) {
//       scoreDelta += 12;
//       reasons.push("Long redirect chain");
//     } else if (redirects.length > 0) {
//       scoreDelta += 4;
//     }
//   } catch (err: any) {
//     if (err?.response?.redirectUrls) {
//       details.redirectCount = err.response.redirectUrls.length;
//       if (err.response.redirectUrls.length >= 3) {
//         scoreDelta += 12;
//         reasons.push("Long redirect chain (error during fetch)");
//       }
//     } else {
//       details.fetchError = String(err.message || err);
//     }
//   }

//   return { scoreDelta, reasons, details };
// }

// // Helper: whois check
// async function whoisCheck(regDomain: string, hostname: string) {
//   const reasons: string[] = [];
//   const details: Record<string, any> = {};
//   let scoreDelta = 0;

//   try {
//     const whoisRaw = await whois(regDomain || hostname);
//     const whoisInfo: any = Array.isArray(whoisRaw) ? (whoisRaw[0] || {}) : (whoisRaw || {});
//     details.whois = {
//       registrar: whoisInfo.registrar || whoisInfo["Registrar"],
//       creationDate: whoisInfo.creationDate || whoisInfo.createdDate || whoisInfo["Creation Date"],
//       updatedDate: whoisInfo.updatedDate || whoisInfo.updated,
//       raw: undefined
//     };

//     const cd = details.whois.creationDate ? new Date(details.whois.creationDate) : null;
//     if (cd) {
//       const ageDays = Math.floor((Date.now() - cd.getTime()) / (1000 * 60 * 60 * 24));
//       details.domainAgeDays = ageDays;
//       if (ageDays < 90) {
//         scoreDelta += 10;
//         reasons.push("Domain is recently created (<90 days)");
//       } else if (ageDays < 365) {
//         scoreDelta += 4;
//       } else {
//         scoreDelta -= 2;
//       }
//     }
//   } catch (err) {
//     details.whoisError = String(err);
//   }

//   return { scoreDelta, reasons, details };
// }

// // Orchestrator: analyzeUrl (uses small helpers)
// async function analyzeUrl(inputUrl: string): Promise<CheckResult> {
//   const normalized = normalizeAndParse(inputUrl);
//   if (normalized.error) {
//     console.error("URL parse error:", normalized.error);
//     return {
//       url: inputUrl,
//       score: 100,
//       verdict: "phishing",
//       reasons: ["Invalid URL format"],
//       details: { error: normalized.error }
//     };
//   }

//   const parsed = normalized.parsed as URL;
//   let score = 0;
//   const reasons: string[] = [];
//   const details: Record<string, any> = {};

//   // Surface checks
//   const surface = surfaceChecks(parsed, inputUrl);
//   score += surface.scoreDelta;
//   reasons.push(...surface.reasons);
//   Object.assign(details, surface.details);

//   // DNS
//   const dnsRes = await dnsCheck(parsed.hostname);
//   score += dnsRes.scoreDelta;
//   reasons.push(...dnsRes.reasons);
//   Object.assign(details, dnsRes.details);

//   // Redirects
//   const redirectRes = await redirectCheck(parsed.href);
//   score += redirectRes.scoreDelta;
//   reasons.push(...redirectRes.reasons);
//   Object.assign(details, redirectRes.details);

//   // Whois / domain age
//   const whoisRes = await whoisCheck(surface.regDomain || parsed.hostname, parsed.hostname);
//   score += whoisRes.scoreDelta;
//   reasons.push(...whoisRes.reasons);
//   Object.assign(details, whoisRes.details);

//   // clamp
//   if (score < 0) score = 0;
//   if (score > 100) score = 100;

//   const verdict = scoreToVerdict(score);
//   if (verdict === "safe") {
//     reasons.unshift("No strong indicators of phishing found");
//   }

//   return {
//     url: parsed.href,
//     score: Math.round(score),
//     verdict,
//     reasons,
//     details
//   };
// }



app.post("/api/check", async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Missing 'url' in body" });
  }

  try {
    const result = await analyzeUrl(url);
    return res.json(result);
  } catch (err) {
    console.error("analyze error:", err);
    return res.status(500).json({ error: "Server error", detail: String(err) });
  }
});


const port = process.env.PORT || 4000;
app.listen(port, () => console.log(`Phisherman backend listening on ${port}`));
