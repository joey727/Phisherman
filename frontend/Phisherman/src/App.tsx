import React, { useState } from "react";

type Result = {
  url: string;
  score: number;
  verdict: "safe" | "suspicious" | "phishing";
  reasons: string[];
  details?: any;
};

function App() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleCheck(e?: React.FormEvent) {
    e?.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);
    try {
      const resp = await fetch("http://localhost:4000/api/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
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
    <div
      style={{
        maxWidth: 760,
        margin: "2rem auto",
        fontFamily: "system-ui, sans-serif",
      }}
    >
      <h1>Phisherman — URL scanner</h1>
      <form onSubmit={handleCheck} style={{ display: "flex", gap: 8 }}>
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="input URL to check"
          style={{ flex: 1, padding: "0.5rem" }}
        />
        <button type="submit" disabled={loading}>
          Check
        </button>
      </form>

      {loading && <p>Checking…</p>}
      {error && <p style={{ color: "red" }}>{error}</p>}

      {result && (
        <div
          style={{
            marginTop: 20,
            border: "1px solid #eee",
            padding: 16,
            borderRadius: 8,
          }}
        >
          <h2>Result: {result.verdict.toUpperCase()}</h2>
          <p>Score: {result.score} / 100</p>

          <div>
            <strong>Reasons:</strong>
            <ul>
              {result.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>

          <details>
            <summary>Raw details</summary>
            <pre style={{ whiteSpace: "pre-wrap" }}>
              {JSON.stringify(result.details, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </div>
  );
}

export default App;
