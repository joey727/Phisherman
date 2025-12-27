export function LoadingSpinner() {
  return (
    <div className="loading-container">
      <div className="spinner" />
      <p className="loading-text">Analyzing URL...</p>
      <style>{`
        .loading-container {
          display: flex;
          flex-direction: column;
          align-items: center;
          gap: 1rem;
        }
        .spinner {
          width: 40px;
          height: 40px;
          border: 3px solid rgba(255, 255, 255, 0.1);
          border-top-color: var(--color-primary);
          border-radius: 50%;
          animation: spin 1s linear infinite;
        }
        .loading-text {
          font-family: var(--font-mono);
          font-size: 0.9rem;
          color: var(--color-primary);
          animation: pulse 1.5s ease-in-out infinite;
        }
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
        @keyframes pulse {
          0%, 100% { opacity: 0.5; }
          50% { opacity: 1; }
        }
      `}</style>
    </div>
  );
}