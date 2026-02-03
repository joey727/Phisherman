import { Checker, CheckResult } from "./types";

class CheckerRegistry {
    private checkers: Checker[] = [];

    register(checker: Checker) {
        this.checkers.push(checker);
    }

    getCheckers(): Checker[] {
        return this.checkers;
    }

    async runAll(url: string): Promise<{ checks: CheckResult[]; timing: Record<string, number> }> {
        const timing: Record<string, number> = {};
        const TIMEOUT_MS = 2500; // 2.5s maximum per checker

        const checks = await Promise.all(
            this.checkers.map(async (checker) => {
                const start = Date.now();
                try {
                    const checkPromise = checker.check(url);
                    const timeoutPromise = new Promise<CheckResult>((_, reject) =>
                        setTimeout(() => reject(new Error("Timeout")), TIMEOUT_MS)
                    );

                    const result = await Promise.race([checkPromise, timeoutPromise]);
                    timing[checker.name] = Date.now() - start;
                    return result;
                } catch (err: any) {
                    timing[checker.name] = Date.now() - start;
                    if (err.message === "Timeout") {
                        console.warn(`Checker ${checker.name} timed out for ${url}`);
                        return { score: 0, reason: `Checker ${checker.name} timed out` };
                    }
                    console.error(`Checker ${checker.name} failed:`, err);
                    return { score: 0, reason: `Checker ${checker.name} error` };
                }
            })
        );

        return { checks, timing };
    }
}

export const registry = new CheckerRegistry();
