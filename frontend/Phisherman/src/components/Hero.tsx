import { useState } from "react";
import { URLInput } from "./URLInput";
import { ResultCard } from "./ResultCard";
import { LoadingSpinner } from "./LoadingSpinner";

type Result = {
    url: string;
    score: number;
    verdict: "safe" | "suspicious" | "phishing";
    reasons: string[];
    details?: any;
};

export function Hero() {
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState<Result | null>(null);
    const [error, setError] = useState<string | null>(null);

    async function handleCheck(urlToCheck: string) {
        if (!urlToCheck.trim()) return;

        setError(null);
        setResult(null);
        setLoading(true);

        try {
            const resp = await fetch("https://phisherman-5r1o.onrender.com/api/check", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: urlToCheck }),
            });

            if (!resp.ok) {
                const body = await resp.json();
                throw new Error(body.error || "Request failed");
            }

            const data: Result = await resp.json();
            setResult(data);
        } catch (err: any) {
            setError(err.message || String(err));
        } finally {
            setLoading(false);
        }
    }

    return (
        <section className="hero-section">
            <div className="container hero-content">
                <h1 className="hero-title">
                    Don't Get <span className="text-gradient">Hooked.</span>
                </h1>
                <p className="hero-subtitle">
                    Real-time phishing detection. Verify any link before you click.
                </p>

                <div className="tool-container">
                    <URLInput onCheck={handleCheck} loading={loading} />

                    {loading && (
                        <div style={{ marginTop: '2rem' }}>
                            <LoadingSpinner />
                        </div>
                    )}

                    {error && (
                        <div className="error-banner glass-panel">
                            ⚠️ {error}
                        </div>
                    )}

                    {result && <ResultCard result={result} />}
                </div>
            </div>
            <style>{`
        .hero-section {
          min-height: 90vh;
          display: flex;
          align-items: center;
          justify-content: center;
          position: relative;
          padding-top: 4rem; /* For fixed nav */
          background: radial-gradient(circle at 50% 10%, rgba(59, 130, 246, 0.15), transparent 60%);
        }
        .hero-content {
          text-align: center;
          z-index: 10;
        }
        .hero-title {
          font-size: 5rem;
          font-weight: 800;
          line-height: 1.1;
          margin-bottom: 1.5rem;
          letter-spacing: -2px;
        }
        .hero-subtitle {
          font-size: 1.25rem;
          color: var(--color-text-muted);
          max-width: 600px;
          margin: 0 auto 3rem;
        }
        .error-banner {
          margin-top: 1rem;
          padding: 1rem;
          color: #ef4444;
          background: rgba(239, 68, 68, 0.1);
          border-color: rgba(239, 68, 68, 0.2);
        }
        @media (max-width: 768px) {
          .hero-title {
            font-size: 3rem;
          }
        }
      `}</style>
        </section>
    );
}
