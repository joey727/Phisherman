

export function Footer() {
  return (
    <footer className="footer">
      <div className="container">
        <p className="copyright">© {new Date().getFullYear()} Phisherman. Open Source Security.</p>
      </div>
      <style>{`
        .footer {
          padding: 3rem 0;
          text-align: center;
          border-top: 1px solid var(--color-border);
          margin-top: 4rem;
        }
        .copyright {
          color: var(--color-text-muted);
          font-size: 0.9rem;
        }
      `}</style>
    </footer>
  );
}
