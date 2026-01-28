export interface CheckResult {
    score: number;
    reason?: string;
    reasons?: string[];
}

export interface Checker {
    name: string;
    check: (url: string) => Promise<CheckResult>;
}

export interface ScanResult {
    url: string;
    score: number;
    verdict: "phishing" | "suspicious" | "safe";
    reasons: string[];
    executionTimeMs?: Record<string, number>;
}
