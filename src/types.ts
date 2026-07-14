export interface CheckResult {
    score: number;
    reason?: string;
    reasons?: string[];
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
}

export interface ScanResult {
    url: string;
    score: number;
    verdict: "phishing" | "suspicious" | "safe";
    threatType?: "phishing" | "malware" | "unwanted_software" | "mixed";
    reasons: string[];
    mlConfidence?: number;
    executionTimeMs?: Record<string, number>;
}

export type ApiKeyTier = "free" | "pro" | "enterprise";

export interface ApiKeyMetadata {
    hash: string;
    prefix: string;
    name: string;
    tier: ApiKeyTier;
    enabled: boolean;
    createdAt: number;
    lastUsedAt: number | null;
}

export const TIER_CONFIGS: Record<ApiKeyTier, { maxRequests: number; windowSeconds: number; maxConcurrent: number }> = {
    free: { maxRequests: 1000, windowSeconds: 3600, maxConcurrent: 10 },
    pro: { maxRequests: 10000, windowSeconds: 3600, maxConcurrent: 50 },
    enterprise: { maxRequests: 100000, windowSeconds: 3600, maxConcurrent: 200 },
};

declare global {
    namespace Express {
        interface Request {
            apiKey?: ApiKeyMetadata;
            isAdmin?: boolean;
        }
    }
}
