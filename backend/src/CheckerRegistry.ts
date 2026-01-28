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

        const checks = await Promise.all(
            this.checkers.map(async (checker) => {
                const start = Date.now();
                try {
                    const result = await checker.check(url);
                    timing[checker.name] = Date.now() - start;
                    return result;
                } catch (err) {
                    console.error(`Checker ${checker.name} failed:`, err);
                    timing[checker.name] = Date.now() - start;
                    return { score: 0, reason: `Checker ${checker.name} error` };
                }
            })
        );

        return { checks, timing };
    }
}

export const registry = new CheckerRegistry();
