import { Checker, CheckResult, ParsedUrl } from "../types";
import { scoreUrlMl } from "../utils/ml";

export async function mlCheck(
  url: string,
  parsed?: ParsedUrl,
): Promise<CheckResult> {
  try {
    // meta can be extended in future; for now pass empty
    const { score, reasons } = await scoreUrlMl(url, {});
    return { score, reasons };
  } catch (err) {
    return { score: 0 };
  }
}

export const MlChecker: Checker = {
  name: "ml",
  check: mlCheck,
};
