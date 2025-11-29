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
      <div className="input-wrapper">
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          disabled={loading}
          className="url-input"
          autoFocus
        />
        <button
          type="submit"
          disabled={loading || !url.trim()}
          className="check-button"
        >
          {loading ? "Checking..." : "Check"}
        </button>
      </div>
    </form>
  );
}