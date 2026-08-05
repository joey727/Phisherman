// Legitimate, registrable apex domains for well-known brands and platforms.
//
// Threat-intel checkers flag a URL host-level (e.g. score 80) when the apex is
// listed in a feed. That is safe for attacker-controlled apexes, but it
// over-flags legitimate platforms whose official apex occasionally appears in a
// feed (e.g. phishing hosted on `vercel.com/login?next=...` puts the whole
// `vercel.com` apex in the feed's host set). For these trusted apexes we keep
// the exact-URL match but suppress the host-level match.
//
// Mirrors ml-service/app/features.py TRUSTED_APEX.
export const TRUSTED_APEX: ReadonlySet<string> = new Set([
    // Brands
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "chase", "wellsfargo", "bankofamerica", "citi",
    "usps", "dhl", "fedex", "ups", "dropbox", "linkedin", "twitter", "ebay",
    "yahoo", "outlook", "office365", "icloud", "coinbase", "binance",
    // Platforms / common safe apexes
    "github", "wikipedia", "reddit", "stackoverflow", "mozilla", "bing",
    "bbc", "nytimes", "office", "githubusercontent", "wix", "medium",
    "wordpress", "squarespace", "gitlab", "cloudflare", "vercel", "netlify",
    "render", "stripe", "heroku", "fly", "digitalocean", "linode",
]);

export function isTrustedApex(hostname: string): boolean {
    if (!hostname) {
        return false;
    }
    // Only suppress host-level intel matches for the bare official apex or its
    // "www." host (e.g. "vercel.com" / "www.vercel.com" — not
    // "evil-vercel.com" or an arbitrary "user-1234.render.com" subdomain, which
    // can host real phishing and must still be host-matchable).
    const labels = hostname.toLowerCase().split(".");
    if (labels.length < 2) {
        return false;
    }
    const apex = labels[labels.length - 2];
    if (!TRUSTED_APEX.has(apex)) {
        return false;
    }
    if (labels.length === 2) {
        return true; // e.g. "vercel.com"
    }
    return labels.length === 3 && labels[0] === "www"; // e.g. "www.vercel.com"
}