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
        return { className: "verdict-safe", icon: "✓", label: "Safe" };
      case "suspicious":
        return {
          className: "verdict-suspicious",
          icon: "⚠",
          label: "Suspicious",
        };
      case "phishing":
        return { className: "verdict-phishing", icon: "✕", label: "Phishing" };
      default:
        return { className: "", icon: "?", label: "Unknown" };
    }
  };

  const verdictStyle = getVerdictStyles(result.verdict);
  const scorePercentage = result.score;
  const scoreColor =
    scorePercentage < 30
      ? "#10b981"
      : scorePercentage < 60
      ? "#f59e0b"
      : "#ef4444";

  return (
    <div className={`result-card ${verdictStyle.className}`}>
      <div className="verdict-header">
        <div className="verdict-icon">{verdictStyle.icon}</div>
        <div>
          <h2 className="verdict-title">{verdictStyle.label}</h2>
          <p className="url-display">{result.url}</p>
        </div>
      </div>

      <div className="score-section">
        <div className="score-label">Risk Score</div>
        <div className="score-bar-container">
          <div
            className="score-bar-fill"
            style={{
              width: `${scorePercentage}%`,
              backgroundColor: scoreColor,
            }}
          />
        </div>
        <div className="score-value" style={{ color: scoreColor }}>
          {result.score} / 100
        </div>
      </div>

      {result.reasons.length > 0 && (
        <div className="reasons-section">
          <h3 className="reasons-title">Findings</h3>
          <ul className="reasons-list">
            {result.reasons.map((reason, idx) => (
              <li key={idx} className="reason-item">
                {reason}
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.details && (
        <button
          className="details-toggle"
          onClick={() => setShowDetails(!showDetails)}
        >
          {showDetails ? "Hide" : "Show"} Technical Details
        </button>
      )}

      {showDetails && result.details && (
        <div className="details-section">
          <pre className="details-json">
            {JSON.stringify(result.details, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
