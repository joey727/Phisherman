import { useState } from "react";

type Result = {
  url: string;
  score: number;
  verdict: "safe" | "suspicious" | "phishing";
  reasons: string[];
  details?: any;
};

type Props = {
  result: Result;
};

export function ResultCard({ result }: Props) {
  const [showDetails, setShowDetails] = useState(false);

  const getVerdictStyles = (verdict: string) => {
    switch (verdict) {
      case "safe":
        return { color: "#10b981", icon: "🛡️", label: "Safe" };
      case "suspicious":
        return { color: "#f59e0b", icon: "⚠️", label: "Suspicious" };
      case "phishing":
        return { color: "#ef4444", icon: "⛔", label: "Phishing" };
      default:
        return { color: "#94a3b8", icon: "?", label: "Unknown" };
    }
  };

  const { color, icon, label } = getVerdictStyles(result.verdict);

  return (
    <div className="result-card glass-panel animate-fade-in">
      <div className="result-header">
        <div className="verdict-badge" style={{ borderColor: color, color: color }}>
          <span className="verdict-icon">{icon}</span>
          <span className="verdict-label">{label}</span>
        </div>
        <div className="score-ring" style={{ borderColor: color }}>
          <span className="score-number" style={{ color }}>{result.score}</span>
          <span className="score-text">RISK SCORE</span>
        </div>
      </div>

      <div className="url-container">
        <code className="url-text">{result.url}</code>
      </div>

      {result.reasons.length > 0 && (
        <div className="reasons-list">
          {result.reasons.map((reason, idx) => (
            <div key={idx} className="reason-item">
              <span className="bullet" style={{ backgroundColor: color }}></span>
              {reason}
            </div>
          ))}
        </div>
      )}

      {result.details && (
        <div className="details-wrapper">
          <button
            className="toggle-details"
            onClick={() => setShowDetails(!showDetails)}
          >
            {showDetails ? "Hide Technical Details" : "View Technical Details"}
          </button>

          {showDetails && (
            <pre className="details-json glass-panel">
              {JSON.stringify(result.details, null, 2)}
            </pre>
          )}
        </div>
      )}

      <style>{`
        .result-card {
          margin-top: 2rem;
          padding: 2rem;
          width: 100%;
          max-width: 600px;
          margin-left: auto;
          margin-right: auto;
          border: 1px solid ${color}40;
          box-shadow: 0 0 30px ${color}20;
        }
        .result-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 1.5rem;
        }
        .verdict-badge {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          padding: 0.5rem 1rem;
          border: 1px solid;
          border-radius: 50px;
          background: ${color}10;
          font-weight: 700;
          font-size: 1.2rem;
          text-transform: uppercase;
        }
        .score-ring {
          text-align: right;
          display: flex;
          flex-direction: column;
          align-items: flex-end;
        }
        .score-number {
          font-size: 2rem;
          font-weight: 800;
          line-height: 1;
        }
        .score-text {
          font-size: 0.6rem;
          letter-spacing: 1px;
          opacity: 0.7;
        }
        .url-container {
          background: var(--color-surface);
          padding: 1rem;
          border-radius: 8px;
          margin-bottom: 1.5rem;
          overflow-x: auto;
        }
        .url-text {
          font-family: var(--font-mono);
          color: var(--color-text-main);
        }
        .reason-item {
          display: flex;
          align-items: flex-start;
          gap: 0.75rem;
          margin-bottom: 0.5rem;
          font-size: 0.95rem;
          color: var(--color-text-muted);
        }
        .bullet {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          margin-top: 0.6em;
          flex-shrink: 0;
        }
        .toggle-details {
          background: none;
          border: none;
          color: var(--color-text-muted);
          font-size: 0.85rem;
          text-decoration: underline;
          margin-top: 1rem;
          cursor: pointer;
        }
        .details-json {
          margin-top: 1rem;
          padding: 1rem;
          font-size: 0.8rem;
          overflow-x: auto;
          background: var(--color-surface);
        }
        .animate-fade-in {
          animation: fadeIn 0.5s ease-out;
        }
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(10px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
