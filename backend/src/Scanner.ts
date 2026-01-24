import { checkPhishTank } from "./checkers/phishtank";
import { checkSafeBrowsing } from "./checkers/googleSafeBrowsing";
import { heuristicCheck } from "./checkers/heuristics";
import { checkOpenPhish } from "./checkers/openPhish";
import { checkGoogleWebRisk } from "./checkers/googleWebRisk";
import { checkURLHaus } from "./checkers/urlHaus";

interface Check {
  score: number;
  reason?: string;
  reasons?: string[];
}

export async function analyzeUrl(url: string) {

  const checks: Check[] = await Promise.all([
    heuristicCheck(url),
    checkOpenPhish(url),
    checkSafeBrowsing(url),
    // checkPhishTank(url),
    // checkGoogleWebRisk(url),
    checkURLHaus(url),
  ]);

  const totalScore = Math.min(
    100,
    checks.reduce((a, c) => a + c.score, 0)
  );

  const verdict =
    totalScore >= 70 ? "phishing" : totalScore >= 40 ? "suspicious" : "safe";

  // Collect all reasons
  const allReasons: string[] = [];
  for (const c of checks) {
    if (c.reasons && Array.isArray(c.reasons)) {
      allReasons.push(...c.reasons);
    }
    if (c.reason) {
      allReasons.push(c.reason);
    }
  }

  return {
    url,
    score: totalScore,
    verdict,
    reasons: allReasons,
  };
}
