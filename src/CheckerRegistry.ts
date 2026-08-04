import { Checker, CheckResult, ParsedUrl, ApiKeyTier } from "./types";

class CheckerRegistry {
  private readonly checkers: Checker[] = [];

  register(checker: Checker) {
    this.checkers.push(checker);
  }

  getCheckers(): Checker[] {
    return this.checkers;
  }

  async runAll(
    url: string,
    parsed?: ParsedUrl,
    opts?: { tier?: ApiKeyTier },
  ): Promise<{ checks: CheckResult[]; timing: Record<string, number> }> {
    const timing: Record<string, number> = {};
    const TIMEOUT_MS = 2500; // 2.5s maximum per checker
    const tier = opts?.tier ?? "free";

    const eligible = this.checkers.filter((checker) => {
      if (!checker.minTier || checker.minTier === "free") return true;
      return tier === "pro" || tier === "enterprise";
    });

    const checks = await Promise.all(
      eligible.map(async (checker) => {
        const start = Date.now();
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          const checkPromise = checker.check(url, parsed);
          const timeoutPromise = new Promise<CheckResult>((_, reject) => {
            timer = setTimeout(() => reject(new Error("Timeout")), TIMEOUT_MS);
          });

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
        } finally {
          if (timer !== undefined) clearTimeout(timer);
        }
      }),
    );

    return { checks, timing };
  }
}

export const registry = new CheckerRegistry();
