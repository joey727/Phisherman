import { checkPhishTank } from "./checkers/phishtank";
import { checkSafeBrowsing } from "./checkers/googleSafeBrowsing";
import { heuristicCheck } from "./checkers/heuristics";
import { checkOpenPhish } from "./checkers/openPhish";
import { checkGoogleWebRisk } from "./checkers/googleWebRisk";
import { checkURLHaus } from "./checkers/urlHaus";

interface Check {
  score: number;
  reason?: string;
}

export async function analyzeUrl(url: string) {

  const checks: Check[] = await Promise.all([
    heuristicCheck(url),
    checkOpenPhish(url),
    checkSafeBrowsing(url),
    checkPhishTank(url),
    checkGoogleWebRisk(url),
    checkURLHaus(url),
  ]);

  const totalScore = Math.min(
    100,
    checks.reduce((a, c) => a + c.score, 0)
  );

  const verdict =
    totalScore >= 70 ? "phishing" : totalScore >= 40 ? "suspicious" : "safe";

  return {
    url,
    score: totalScore,
    verdict,
    reasons: checks.filter((c) => c.reason).map((c) => c.reason),
  };
}
