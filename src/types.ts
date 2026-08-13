export interface CheckResult {
    score: number;
    reason?: string;
    reasons?: string[];
    /** Checker that produced this result (set by CheckerRegistry.runAll). */
    name?: string;
    /**
     * Established-domain veto: set by a checker when the URL's registered domain
     * is established (whois age >= 365d) and the URL is lexically clean. When any
     * check vetoes, analyzeUrl drops the ML checker's score contribution.
     */
    veto?: boolean;
}

export interface ParsedUrl {
    raw: string;
    hostname: string;
    protocol: string;
    normalized: string;
}

export interface Checker {
    name: string;
    check: (url: string, parsed?: ParsedUrl) => Promise<CheckResult>;
    minTier?: "free" | "pro";
}

export interface ScanResult {
    url: string;
    score: number;
    verdict: "phishing" | "suspicious" | "safe";
    threatType?: "phishing" | "malware" | "unwanted_software" | "mixed";
    reasons: string[];
    mlConfidence?: number;
    executionTimeMs?: Record<string, number>;
    tier: ApiKeyTier;
}

export type ApiKeyTier = "free" | "pro" | "enterprise";

export interface ApiKeyMetadata {
    hash: string;
    prefix: string;
    name: string;
    email?: string;
    tier: ApiKeyTier;
    enabled: boolean;
    createdAt: number;
    lastUsedAt: number | null;
}

export const TIER_CONFIGS: Record<ApiKeyTier, { maxRequests: number; windowSeconds: number; maxConcurrent: number }> = {
    free: { maxRequests: 3, windowSeconds: 86400, maxConcurrent: 1 },
    pro: { maxRequests: 50, windowSeconds: 86400, maxConcurrent: 5 },
    enterprise: { maxRequests: 100, windowSeconds: 86400, maxConcurrent: 10 },
};

declare global {
    namespace Express {
        interface Request {
            apiKey?: ApiKeyMetadata;
            isAdmin?: boolean;
        }
    }
}
