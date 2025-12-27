

export function Features() {
  const features = [
    {
      title: "Advanced Analysis",
      desc: "Smart algorithms analyze URL patterns and content in real-time.",
      icon: "🔍"
    },
    {
      title: "Instant Verdict",
      desc: "Get immediate results. Safe, Suspicious, or Phishing.",
      icon: "⚡"
    },
    {
      title: "Privacy First",
      desc: "We don't track your history. Your safety is our only priority.",
      icon: "🛡️"
    }
  ];

  return (
    <section id="features" className="features-section">
      <div className="container">
        <div className="features-grid">
          {features.map((f, i) => (
            <div key={i} className="feature-card glass-panel">
              <div className="feature-icon">{f.icon}</div>
              <h3 className="feature-title">{f.title}</h3>
              <p className="feature-desc">{f.desc}</p>
            </div>
          ))}
        </div>
      </div>
      <style>{`
        .features-section {
          padding: 6rem 0;
        }
        .features-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
          gap: 2rem;
        }
        .feature-card {
          padding: 2rem;
          transition: transform 0.3s ease;
        }
        .feature-card:hover {
          transform: translateY(-5px);
          background: var(--color-surface-hover);
        }
        .feature-icon {
          font-size: 2.5rem;
          margin-bottom: 1rem;
        }
        .feature-title {
          font-size: 1.25rem;
          margin-bottom: 0.5rem;
          font-family: var(--font-mono);
        }
        .feature-desc {
          color: var(--color-text-muted);
          font-size: 0.95rem;
        }
      `}</style>
    </section>
  );
}
