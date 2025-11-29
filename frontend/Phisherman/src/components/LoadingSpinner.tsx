export function LoadingSpinner() {
  return (
    <div className="loading-container">
      <div className="spinner" />
      <p className="loading-text">Analyzing URL...</p>
    </div>
  );
}