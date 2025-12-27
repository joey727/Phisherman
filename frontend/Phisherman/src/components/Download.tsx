

export function Download() {
  return (
    <section id="download" className="download-section">
      <div className="container download-content">
        <h2 className="section-title text-gradient">Secure Your Browser</h2>
        <p className="section-subtitle">Install the extension for automatic protection as you browse.</p>

        <div className="cta-group">
          <button className="cta-button primary">
            <span className="icon">⬇</span> Add to Chrome
          </button>
          <button className="cta-button secondary">
            <span className="icon">🦊</span> Add to Firefox
          </button>
        </div>
      </div>
      <style>{`
        .download-section {
          padding: 4rem 0;
          text-align: center;
        }
        .section-title {
          font-size: 2.5rem;
          margin-bottom: 1rem;
        }
        .section-subtitle {
          color: var(--color-text-muted);
          margin-bottom: 3rem;
          font-size: 1.1rem;
        }
        .cta-group {
          display: flex;
          gap: 1.5rem;
          justify-content: center;
          flex-wrap: wrap;
        }
        .cta-button {
          padding: 1rem 2rem;
          border-radius: 50px;
          font-weight: 600;
          font-size: 1rem;
          display: flex;
          align-items: center;
          gap: 0.5rem;
          transition: transform 0.2s, box-shadow 0.2s;
          border: none;
        }
        .cta-button:hover {
          transform: translateY(-2px);
          box-shadow: 0 10px 20px -5px rgba(0,0,0,0.5);
        }
        .cta-button.primary {
          background: var(--color-primary);
          color: white;
          box-shadow: 0 0 15px var(--color-primary-glow);
        }
        .cta-button.secondary {
          background: var(--color-surface);
          color: #1e293b;
          border: 1px solid rgba(0,0,0,0.1);
        }
        @media (prefers-color-scheme: dark) {
          .cta-button.secondary {
            color: white;
            border: 1px solid var(--color-border);
          }
        }
      `}</style>
    </section>
  );
}
