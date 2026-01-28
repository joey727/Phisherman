import { registry } from "./CheckerRegistry";
import { HeuristicsChecker } from "./checkers/heuristics";
import { OpenPhishChecker } from "./checkers/openPhish";
import { SafeBrowsingChecker } from "./checkers/googleSafeBrowsing";
import { URLHausChecker } from "./checkers/urlHaus";
import { PhishTankChecker } from "./checkers/phishtank";
import { WebRiskChecker } from "./checkers/googleWebRisk";
import { PhishStatsChecker } from "./checkers/phishStats";
import { ScanResult } from "./types";

// Register all checkers
registry.register(HeuristicsChecker);
registry.register(OpenPhishChecker);
registry.register(SafeBrowsingChecker);
registry.register(URLHausChecker);
registry.register(PhishTankChecker);
registry.register(WebRiskChecker);
registry.register(PhishStatsChecker);

export async function analyzeUrl(url: string): Promise<ScanResult> {
  const { checks, timing } = await registry.runAll(url);

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
    executionTimeMs: timing,
  };
}

