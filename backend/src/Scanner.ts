import { checkPhishTank } from "./checkers/phishtank";
import { checkSafeBrowsing } from "./checkers/googleSafeBrowsing";
import { heuristicCheck } from "./checkers/heuristics";

interface Check {
    score: number;
    reason?: string;
}

export async function analyzeUrl(url: string) {
  const checks: Check[] = await Promise.all([
    heuristicCheck(url),
    checkSafeBrowsing(url),
    checkPhishTank(url),
  ]);

  const totalScore = Math.min(
    100,
    checks.reduce((a, c) => a + c.score, 0)
  );

  const verdict =
    totalScore >= 70
      ? "phishing"
      : totalScore >= 40
      ? "suspicious"
      : "safe";

  return {
    url,
    score: totalScore,
    verdict,
    reasons: checks.filter(c => c.reason).map(c => c.reason),
  };
}
