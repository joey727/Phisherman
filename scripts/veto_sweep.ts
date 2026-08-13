require("dotenv").config();
const { HeuristicsChecker } = require("../src/checkers/heuristics");

const urls = [
  "https://docs.python.org/library/",
  "https://www.python.org/",
  "https://www.postgresql.org/",
  "https://postgresql.org/docs/",
  "https://www.gnu.org/",
  "https://nodejs.org/en",
  "https://getbootstrap.com/",
  "https://webpack.js.org/",
  "https://www.archlinux.org/",
  "https://reactjs.org/docs/",
  "https://www.docker.com/",
  "https://docs.docker.com/get-started/",
  "https://kubernetes.io/",
  "https://archive.org/details/",
  "https://www.w3.org/TR/html/",
  "https://news.ycombinator.com/",
  "https://www.anthropic.com/",
  "https://www.miele.com/",
  "https://www.leica-camera.com/",
  "https://www.napaonline.com/",
  "https://www.goodyear.com/",
  "https://www.hollisterco.com/",
  "https://www.quizlet.com/",
  "https://firehydrant.io/",
  "https://oncall.tools/",
];

(async () => {
  const fails = [];
  for (const u of urls) {
    const r = await HeuristicsChecker.check(u);
    const ok = r.veto === true;
    if (!ok) fails.push(`${u}  veto=${r.veto}`);
    console.log(`${ok ? "OK " : "MISS"} ${u.padEnd(36)} veto=${String(r.veto).padStart(5)} score=${String(r.score).padStart(3)}`);
  }
  console.log("\nFAILURES:", fails.length);
  process.exit(0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});