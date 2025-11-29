import { useState } from "react";
import "./App.css";
import { URLInput } from "./components/URLInput";
import { ResultCard } from "./components/ResultCard";
import { LoadingSpinner } from "./components/LoadingSpinner";

type Result = {
  url: string;
  score: number;
  verdict: "safe" | "suspicious" | "phishing";
  reasons: string[];
  details?: any;
};

function App() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleCheck(urlToCheck: string) {
    if (!urlToCheck.trim()) return;

    setError(null);
    setResult(null);
    setLoading(true);

    try {
      const resp = await fetch("http://localhost:4000/api/check", {
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
    <div className="app">
      <header className="header">
        <div className="header-content">
          <div className="title-section">
            <h1 className="title">🎣 Phisherman</h1>
            <p className="subtitle">Check URLs for phishing risks</p>
          </div>
        </div>
      </header>

      <main className="container">
        <URLInput onCheck={handleCheck} loading={loading} />

        {loading && <LoadingSpinner />}

        {error && <div className="error-banner">{error}</div>}

        {result && <ResultCard result={result} />}

        {!loading && !result && !error && (
          <div className="empty-state">
            <p>Enter a URL above to scan for phishing threats</p>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
