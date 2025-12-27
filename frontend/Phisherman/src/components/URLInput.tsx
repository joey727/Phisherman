import React, { useState } from "react";

type Props = {
  onCheck: (url: string) => Promise<void>;
  loading: boolean;
};

export function URLInput({ onCheck, loading }: Props) {
  const [url, setUrl] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onCheck(url);
  };

  return (
    <form onSubmit={handleSubmit} className="url-form">
      <div className="input-wrapper glass-panel">
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="Paste suspicious URL here..."
          disabled={loading}
          className="url-input"
          autoFocus
        />
        <button
          type="submit"
          disabled={loading || !url.trim()}
          className="check-button"
        >
          {loading ? "Scanning..." : "Scan URL"}
        </button>
      </div>
      <style>{`
        .url-form {
          width: 100%;
          max-width: 600px;
          margin: 0 auto;
        }
        .input-wrapper {
          display: flex;
          padding: 0.5rem;
          background: var(--color-surface);
          border: 1px solid var(--color-border);
        }
        .url-input {
          flex: 1;
          background: transparent;
          border: none;
          color: var(--color-text-main);
          padding: 1rem;
          font-size: 1.1rem;
          outline: none;
          min-width: 0;
        }
        .url-input::placeholder {
          color: var(--color-text-muted);
        }
        .check-button {
          background: var(--color-primary);
          color: white;
          border: none;
          padding: 0 2rem;
          border-radius: 8px;
          font-weight: 600;
          font-size: 1rem;
          transition: all 0.2s;
        }
        .check-button:hover:not(:disabled) {
          background: #2563eb;
          box-shadow: 0 0 15px var(--color-primary-glow);
        }
        .check-button:disabled {
          opacity: 0.7;
          cursor: not-allowed;
        }
      `}</style>
    </form>
  );
}