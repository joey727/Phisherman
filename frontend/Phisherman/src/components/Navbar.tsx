

export function Navbar() {
  return (
    <nav className="navbar glass-panel">
      <div className="container nav-content">
        <div className="logo">
          <span className="logo-text">Phisherman</span>
        </div>
        <div className="nav-links">
          <a href="#features" className="nav-link">Features</a>
          <a href="#download" className="nav-link">Download</a>
          <a href="https://github.com/joey727/Phisherman" target="_blank" rel="noopener noreferrer" className="nav-link">Source</a>
        </div>
      </div>
      <style>{`
        .navbar {
          position: fixed;
          top: 1rem;
          left: 50%;
          transform: translateX(-50%);
          width: 90%;
          max-width: 1000px;
          z-index: 100;
          padding: 0.75rem 1.5rem;
          margin: 0 auto;
        }
        .nav-content {
          display: flex;
          justify-content: space-between;
          align-items: center;
        }
        .logo {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          font-weight: 700;
          font-size: 1.25rem;
          color: var(--color-text-main);
        }
        .logo-icon {
          font-size: 1.5rem;
        }
        .nav-links {
          display: flex;
          gap: 2rem;
        }
        .nav-link {
          font-size: 0.9rem;
          color: var(--color-text-muted);
          transition: color 0.2s ease;
        }
        .nav-link:hover {
          color: var(--color-text-main);
        }
        @media (max-width: 600px) {
          .nav-links {
            display: none;
          }
        }
      `}</style>
    </nav>
  );
}
