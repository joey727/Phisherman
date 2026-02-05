import { analyzeUrl } from "../src/Scanner";
import dotenv from "dotenv";

dotenv.config();

async function runBenchmark() {
    const url = "https://google.com";
    const iterations = 5;

    console.log("=== Phisherman Performance Benchmark ===");
    console.log(`Testing URL: ${url} over ${iterations} iterations\n`);

    for (let i = 1; i <= iterations; i++) {
        const start = Date.now();
        const result = await analyzeUrl(url);
        const duration = Date.now() - start;

        console.log(`Iteration ${i}: ${duration}ms`);
        if (result.executionTimeMs) {
            Object.entries(result.executionTimeMs).forEach(([checker, time]) => {
                console.log(`  - ${checker}: ${time}ms`);
            });
        }
        console.log("");
    }

    console.log("\nBenchmark complete.");
    process.exit(0);
}

runBenchmark().catch(err => {
    console.error("Benchmark failed:", err);
    process.exit(1);
});
