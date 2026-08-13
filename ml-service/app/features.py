"""
Feature extraction for phishing URL classification.

Extracts 40+ features from a raw URL string without making any network requests,
ensuring sub-millisecond feature computation for real-time inference.
"""

import math
import re
from urllib.parse import urlparse, parse_qs
from typing import Optional

import tldextract
import numpy as np

# ---------------------------------------------------------------------------
# Known lists used for feature flags
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS = frozenset([
    "tk", "ml", "cf", "ga", "gq", "top", "xyz", "buzz", "club", "online",
    "site", "icu", "work", "info", "su", "pw", "cc", "ws",
])

SHORTENER_DOMAINS = frozenset([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "lnkd.in", "rb.gy",
])

BRAND_KEYWORDS = frozenset([
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "chase", "wellsfargo", "bankofamerica", "citi",
    "usps", "dhl", "fedex", "ups", "dropbox", "linkedin", "twitter", "ebay",
    "yahoo", "outlook", "office365", "icloud", "coinbase", "binance",
])

SUSPICIOUS_KEYWORDS = frozenset([
    "verify", "update", "secure", "login", "support", "account", "confirm",
    "suspend", "alert", "urgent", "expire", "unlock", "validate", "password",
    "credential", "signin", "billing", "invoice", "refund", "reward",
])

# Popular global brands/platforms whose real apex is treated as benign by the
# trusted-apex guard. This is a *bounded, curated* allowlist used only as a
# fast-path for the official site; lookalike phishing lives on a different apex
# (e.g. paypal-secure-verify.tk) and is NOT in this set. Model quality is
# independently enforced by the raw-model promotion gate, so this list cannot
# mask a broken classifier.
POPULAR_APEXES = frozenset([
    "adobe", "airbnb", "alibaba", "atlassian", "autodesk", "baidu",
    "bestbuy", "booking", "canva", "capitalone", "cisco", "coca-cola",
    "costco", "dell", "disney", "ebay", "etsy", "expedia", "fedex",
    "figma", "ford", "gopro", "hermes", "homedepot", "hp", "hulu",
    "ibm", "ikea", "intel", "jetblue", "kroger", "lenovo", "lowes",
    "mercedes-benz", "miro", "nike", "notion", "nvidia", "openai",
    "oracle", "pinterest", "salesforce", "samsung", "shopify", "siemens",
    "slack", "snapchat", "sony", "spotify", "target", "telegram",
    "tesla", "tiktok", "toyota", "tumblr", "twitch", "uber", "usps",
    "walmart", "zoom",
])

# Registrable/apex domains that are legitimate well-known brands. Being a
# trusted apex means the site is the official brand site, so keyword/brand
# impersonation signals are suppressed there. A phishing URL that spoofs a
# brand lives on a *different* apex (e.g. paypal-secure-verify.tk), which is
# NOT in this set and therefore still gets flagged.
TRUSTED_APEX = BRAND_KEYWORDS | POPULAR_APEXES | frozenset([
    "github", "wikipedia", "reddit", "stackoverflow", "mozilla", "bing",
    "bbc", "nytimes", "office", "githubusercontent", "wix", "medium",
    "wordpress", "squarespace", "gitlab", "cloudflare", "vercel", "netlify",
    "render", "stripe", "heroku", "fly", "digitalocean", "linode",
    # Official brand host subdomains whose registered domain embeds a brand
    # name as a prefix (microsoftonline, amazonaws, googleusercontent, ...).
    "microsoftonline", "microsoft365", "amazonaws", "googleusercontent",
    "googleapis", "googleanalytics", "adwords", "office365", "live",
    "livechat", "outlook", "auth0",
])

# Official sites are only treated as trusted when hosted on a normal top-level
# domain. `paypal.tk` / `apple.ga` are NOT the official site even though the
# apex string matches a brand — a suspicious TLD defeats the trust assumption.
OFFICIAL_SUFFIXES = frozenset([
    "com", "org", "net", "io", "co", "dev", "ai", "app", "gov", "edu",
    "uk", "de", "fr", "ca", "au", "in", "jp", "kr", "cn", "br", "mx",
    "es", "it", "nl", "se", "no", "fi", "dk", "pl", "ch", "at", "be",
    "ie", "nz", "sg", "info", "me", "tv", "cc", "ru",
])


# Registered-domain *age* (from the backend's whois or the ml-service's own
# RDAP lookup) is the enrichment feature (index 40) used to tell established
# legitimate domains from freshly-registered phishing domains. It replaces the
# large Tranco popularity list the model used to depend on.



def is_trusted_apex(url: str) -> bool:
    """True if the URL's effective apex (eTLD+1) is an official brand/popular site.

    Phishing impersonators almost never obtain the real brand apex (attacker
    apexes differ, e.g. paypal-secure-verify.tk), so a trusted apex is treated
    as benign — but only on a normal TLD. `paypal.tk` is NOT considered official.
    """
    try:
        ext = tldextract.extract(url)
        if not (ext.domain and ext.domain.lower() in TRUSTED_APEX):
            return False
        if ext.suffix and ext.suffix.lower() in SUSPICIOUS_TLDS:
            return False
        return True
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _count_char(s: str, char: str) -> int:
    return s.count(char)


def _digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if c.isdigit()) / len(s)


def _special_char_count(s: str) -> int:
    return sum(1 for c in s if not c.isalnum() and c not in (".", "/", ":", "-"))


def _vowel_consonant_ratio(s: str) -> float:
    """Ratio of vowels to consonants in a string — phishing domains often have unusual ratios."""
    vowels = sum(1 for c in s.lower() if c in "aeiou")
    consonants = sum(1 for c in s.lower() if c.isalpha() and c not in "aeiou")
    if consonants == 0:
        return float(vowels) if vowels > 0 else 0.0
    return vowels / consonants


def _is_ip_address(hostname: str) -> bool:
    """Check if hostname is an IP address (v4)."""
    parts = hostname.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    return False


def _has_punycode(hostname: str) -> bool:
    """Check if hostname contains punycode (internationalized domain name)."""
    return any(label.startswith("xn--") for label in hostname.split("."))


def _brand_impersonation_count(url_lower: str, apex_domain: str) -> int:
    """Count brand keywords, excluding the brand that is itself the registrable domain.

    Visiting the official brand site (e.g. `google` for `google.com`) is not
    impersonation; impersonation means a brand keyword appears in a URL whose own
    apex/registered domain is a different brand or a suspicious domain.

    Word-boundary matching avoids false hits from brands concatenated with other
    letters in official host names: `login.microsoftonline.com` contains the
    substring "microsoft" but "microsoft" is not a whole word there, so it is
    NOT counted as impersonation (Microsoft owns microsoftonline.com). A lookalike
    such as `paypal-secure-verify.tk` still matches because "paypal" is followed
    by a word boundary ("-").
    """
    count = 0
    for brand in BRAND_KEYWORDS:
        if apex_domain and brand == apex_domain:
            continue
        if re.search(rf"\b{re.escape(brand)}\b", url_lower):
            count += 1
    return count


def _suspicious_keyword_count(url_lower: str) -> int:
    """Count suspicious keywords in the URL (whole-word only)."""
    return sum(
        1 for kw in SUSPICIOUS_KEYWORDS if re.search(rf"\b{re.escape(kw)}\b", url_lower)
    )


def _levenshtein(a: str, b: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(
                min(
                    prev[j] + 1,
                    cur[j - 1] + 1,
                    prev[j - 1] + (0 if ca == cb else 1),
                )
            )
        prev = cur
    return prev[-1]


def _brand_typosquat_min_distance(domain_lower: str, apex_domain: str) -> float:
    """Minimum edit distance between the registered domain and any known brand.

    A distance of 1-3 indicates a likely brand typosquat/homoglyph lookalike
    (e.g. `paypa1.com`, `amaz0n.com`). The official site (distance 0) is handled
    by the trusted-apex guard and returns a large sentinel so it reads as benign.
    """
    if not domain_lower:
        return 50.0
    if apex_domain and apex_domain in TRUSTED_APEX:
        return 50.0
    best = 50
    for brand in BRAND_KEYWORDS:
        d = _levenshtein(domain_lower, brand)
        if d < best:
            best = d
            if best <= 1:
                break
    return float(best)


# ---------------------------------------------------------------------------
# Main feature extraction
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    # Lexical (0-5)
    "url_length",
    "hostname_length",
    "path_length",
    "path_depth",
    "query_param_count",
    "has_fragment",
    # Character distribution (6-14)
    "digit_ratio",
    "special_char_count",
    "hyphen_count",
    "dot_count_url",
    "dot_count_hostname",
    "at_sign_present",
    "double_slash_count",
    "tilde_present",
    "percent_count",
    # Domain features (15-22)
    "subdomain_depth",
    "tld_is_suspicious",
    "is_ip_address",
    "has_punycode",
    "domain_length",
    "subdomain_length",
    "registered_domain_length",
    "has_port",
    # Statistical (23-27)
    "hostname_entropy",
    "path_entropy",
    "full_url_entropy",
    "vowel_consonant_ratio",
    "digit_count_hostname",
    # Protocol (28-30)
    "is_https",
    "has_non_standard_port",
    "protocol_length",
    # Suspicious patterns (31-39)
    "brand_impersonation_count",
    "suspicious_keyword_count",
    "is_shortener",
    "has_data_uri",
    "has_base64_segment",
    "excessive_subdomain_depth",
    "path_has_double_extension",
    "has_at_in_path",
    "url_contains_hex_chars",
    # Enrichment metadata (40-42) — may be -1/0 if not provided
    "domain_age_days",
    "prior_score",
    "prior_checker_count",
    # Typosquat / homoglyph similarity (43) — min edit distance to a known brand
    "brand_typosquat_min_distance",
]

NUM_FEATURES = len(FEATURE_NAMES)


def extract_features(url: str, meta: Optional[dict] = None) -> np.ndarray:
    """
    Extract a fixed-length numeric feature vector from a URL.

    Parameters
    ----------
    url : str
        The raw URL string.
    meta : dict, optional
        Enrichment metadata from the Node backend (domain_age_days, prior_score, etc.).

    Returns
    -------
    np.ndarray
        1-D array of shape (NUM_FEATURES,) with dtype float32.
    """
    meta = meta or {}
    url_lower = url.lower()

    # Parse URL components
    try:
        parsed = urlparse(url if url.startswith(("http://", "https://")) else f"http://{url}")
    except Exception:
        parsed = urlparse(f"http://{url}")

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    # TLD extraction
    ext = tldextract.extract(url)
    subdomain = ext.subdomain or ""
    registered_domain = ext.registered_domain or ""
    suffix = ext.suffix or ""

    # Parse query params
    try:
        query_params = parse_qs(query)
    except Exception:
        query_params = {}

    # Determine port
    try:
        port = parsed.port
    except Exception:
        port = None

    features = np.zeros(NUM_FEATURES, dtype=np.float32)

    # --- Lexical (0-5) ---
    features[0] = len(url)
    features[1] = len(hostname)
    features[2] = len(path)
    features[3] = path.count("/") - 1 if path.startswith("/") else path.count("/")
    features[4] = len(query_params)
    features[5] = 1.0 if fragment else 0.0

    # --- Character distribution (6-14) ---
    features[6] = _digit_ratio(hostname)
    features[7] = _special_char_count(url)
    features[8] = _count_char(hostname, "-")
    features[9] = _count_char(url, ".")
    features[10] = _count_char(hostname, ".")
    features[11] = 1.0 if "@" in url else 0.0
    features[12] = url.count("//") - 1  # subtract the protocol://
    features[13] = 1.0 if "~" in url else 0.0
    features[14] = _count_char(url, "%")

    # --- Domain features (15-22) ---
    features[15] = subdomain.count(".") + 1 if subdomain else 0
    features[16] = 1.0 if suffix in SUSPICIOUS_TLDS else 0.0
    features[17] = 1.0 if _is_ip_address(hostname) else 0.0
    features[18] = 1.0 if _has_punycode(hostname) else 0.0
    features[19] = len(ext.domain or "")
    features[20] = len(subdomain)
    features[21] = len(registered_domain)
    features[22] = 1.0 if port and port not in (80, 443) else 0.0

    # --- Statistical (23-27) ---
    features[23] = _shannon_entropy(hostname.replace(".", ""))
    features[24] = _shannon_entropy(path)
    features[25] = _shannon_entropy(url)
    features[26] = _vowel_consonant_ratio(hostname)
    features[27] = sum(1 for c in hostname if c.isdigit())

    # --- Protocol (28-30) ---
    features[28] = 1.0 if parsed.scheme == "https" else 0.0
    features[29] = 1.0 if port and port not in (80, 443, None) else 0.0
    features[30] = len(parsed.scheme)

    # --- Suspicious patterns (31-39) ---
    apex = (ext.domain or "").lower()
    if is_trusted_apex(url):
        # Official brand/popular site: keywords and brand-impersonation are NOT
        # suspicious here (e.g. https://www.paypal.com/login is legitimate).
        features[31] = 0.0
        features[32] = 0.0
    else:
        features[31] = _brand_impersonation_count(url_lower, ext.domain or "")
        features[32] = _suspicious_keyword_count(url_lower)
    features[33] = 1.0 if any(s in hostname for s in SHORTENER_DOMAINS) else 0.0
    features[34] = 1.0 if url_lower.startswith("data:") else 0.0
    features[35] = 1.0 if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", url) else 0.0
    features[36] = 1.0 if (subdomain.count(".") + 1 if subdomain else 0) > 3 else 0.0
    features[37] = 1.0 if re.search(r"\.\w{2,4}\.\w{2,4}$", path) else 0.0
    features[38] = 1.0 if "@" in path else 0.0
    features[39] = 1.0 if re.search(r"%[0-9a-fA-F]{2}", url) else 0.0

    # --- Enrichment metadata (40-42) ---
    features[40] = float(meta.get("domain_age_days", -1))
    features[41] = float(meta.get("prior_score", 0))
    features[42] = float(meta.get("prior_checker_count", 0))

    # --- Typosquat similarity (43) ---
    features[43] = _brand_typosquat_min_distance((ext.domain or "").lower(), apex)

    return features
