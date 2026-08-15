import { Checker, CheckResult, ParsedUrl } from "../types";
import { scoreUrlMl } from "../utils/ml";

export async function mlCheck(
  url: string,
  parsed?: ParsedUrl,
): Promise<CheckResult> {
  try {
    // Pass enrichment context so the ML model can use domain age, prior scores, etc.
    const meta: Record<string, any> = {};

    if (parsed) {
      meta.hostname = parsed.hostname;
      meta.protocol = parsed.protocol;
    }

    const { score, reasons } = await scoreUrlMl(url, meta);
    return { score, reasons };
  } catch (err) {
    return { score: 0 };
  }
}

export const MlChecker: Checker = {
  name: "ml",
  check: mlCheck,
  minTier: "ml",
};
