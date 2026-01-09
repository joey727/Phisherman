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

const ICONS = {
  safe: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <polyline points="9 12 11 14 15 10" />
    </svg>
  ),
  suspicious: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  ),
  phishing: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
    </svg>
  ),
  info: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="16" x2="12" y2="12" />
      <line x1="12" y1="8" x2="12.01" y2="8" />
    </svg>
  ),
};

export function ResultCard({ result }: Props) {
  const [showDetails, setShowDetails] = useState(false);

  const getVerdictData = (verdict: string) => {
    switch (verdict) {
      case "safe":
        return { color: "var(--color-accent)", label: "Secure Site", icon: ICONS.safe };
      case "suspicious":
        return { color: "var(--color-warning, #f59e0b)", label: "Suspicious Activity", icon: ICONS.suspicious };
      case "phishing":
        return { color: "#ef4444", label: "Phishing Detected", icon: ICONS.phishing };
      default:
        return { color: "var(--color-text-muted)", label: "Unknown", icon: ICONS.info };
    }
  };

  const { color, label, icon } = getVerdictData(result.verdict);

  return (
    <div className="result-card-container animate-fade-in">
      <div className="result-main glass-panel">
        <div className="status-header">
          <div className="status-indicator" style={{ color }}>
            <span className="icon-wrapper">{icon}</span>
            <div className="status-text">
              <h3 className="verdict-label">{label}</h3>
              <p className="domain-text">{new URL(result.url).hostname}</p>
            </div>
          </div>
          <div className="score-badge" style={{ backgroundColor: `${color}15`, color }}>
            <span className="score-num">{result.score}</span>
            <span className="score-lbl">Risk</span>
          </div>
        </div>

        {result.reasons.length > 0 && (
          <div className="analysis-summary">
            <h4 className="section-title">Analysis Insights</h4>
            <ul className="reasons-list">
              {result.reasons.map((reason, idx) => (
                <li key={idx} className="reason-item">
                  <span className="dot" style={{ backgroundColor: color }}></span>
                  {reason}
                </li>
              ))}
            </ul>
          </div>
        )}

        {result.details && (
          <div className="technical-section">
            <button
              className="details-toggle"
              onClick={() => setShowDetails(!showDetails)}
            >
              <span className={`chevron ${showDetails ? 'open' : ''}`}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
              </span>
              {showDetails ? "Hide Forensics" : "View Forensics"}
            </button>

            {showDetails && (
              <div className="details-box">
                <pre>{JSON.stringify(result.details, null, 2)}</pre>
              </div>
            )}
          </div>
        )}
      </div>

      <style>{`
        .result-card-container {
          width: 100%;
          max-width: 640px;
          margin: 3rem auto;
          display: flex;
          flex-direction: column;
          gap: 1.5rem;
        }

        .result-main {
          padding: 2rem;
          background: var(--color-surface);
          border: 1px solid var(--color-border);
          border-radius: var(--radius-xl);
          box-shadow: 0 20px 40px -10px rgba(0,0,0,0.1);
        }

        .status-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          margin-bottom: 2rem;
        }

        .status-indicator {
          display: flex;
          align-items: center;
          gap: 1.25rem;
        }

        .icon-wrapper {
          width: 48px;
          height: 48px;
          display: flex;
          align-items: center;
          justify-content: center;
          flex-shrink: 0;
        }

        .status-text h3 {
          font-size: 1.5rem;
          font-weight: 700;
          margin: 0;
          letter-spacing: -0.02em;
        }

        .domain-text {
          font-size: 0.875rem;
          color: var(--color-text-muted);
          margin: 0.25rem 0 0 0;
          font-family: var(--font-mono);
          opacity: 0.8;
        }

        .score-badge {
          padding: 0.75rem 1rem;
          border-radius: 12px;
          text-align: center;
          display: flex;
          flex-direction: column;
          min-width: 70px;
        }

        .score-num {
          font-size: 1.5rem;
          font-weight: 800;
          line-height: 1;
        }

        .score-lbl {
          font-size: 0.625rem;
          text-transform: uppercase;
          font-weight: 700;
          letter-spacing: 0.05em;
          margin-top: 2px;
          opacity: 0.7;
        }

        .analysis-summary {
          margin-top: 2rem;
          padding-top: 1.5rem;
          border-top: 1px solid var(--color-border);
        }

        .section-title {
          font-size: 0.75rem;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: 0.1em;
          color: var(--color-text-muted);
          margin-bottom: 1rem;
        }

        .reasons-list {
          list-style: none;
          padding: 0;
          margin: 0;
          display: flex;
          flex-direction: column;
          gap: 0.75rem;
        }

        .reason-item {
          display: flex;
          align-items: center;
          gap: 0.75rem;
          font-size: 0.9375rem;
          color: var(--color-text-main);
          line-height: 1.4;
        }

        .dot {
          width: 5px;
          height: 5px;
          border-radius: 50%;
          flex-shrink: 0;
        }

        .technical-section {
          margin-top: 1.5rem;
        }

        .details-toggle {
          background: none;
          border: none;
          color: var(--color-text-muted);
          font-size: 0.8125rem;
          font-weight: 600;
          display: flex;
          align-items: center;
          gap: 0.5rem;
          cursor: pointer;
          padding: 0;
          transition: color 0.2s;
        }

        .details-toggle:hover {
          color: var(--color-text-main);
        }

        .chevron {
          width: 14px;
          height: 14px;
          transition: transform 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .chevron.open {
          transform: rotate(180deg);
        }

        .details-box {
          margin-top: 1rem;
          padding: 1.25rem;
          background: rgba(0,0,0,0.03);
          border-radius: 12px;
          font-family: var(--font-mono);
          font-size: 0.75rem;
          overflow-x: auto;
          border: 1px solid var(--color-border);
        }

        .details-box pre {
          margin: 0;
          line-height: 1.5;
          color: var(--color-text-muted);
        }

        @media (prefers-color-scheme: dark) {
          .details-box {
            background: rgba(255,255,255,0.02);
          }
        }

        .animate-fade-in {
          animation: slideUpFade 0.6s cubic-bezier(0.16, 1, 0.3, 1);
        }

        @keyframes slideUpFade {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
