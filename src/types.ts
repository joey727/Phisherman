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
