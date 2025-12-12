# Phisherman Chrome Extension (dev)

## Load locally

1. Build or copy this folder somewhere local.
2. Open Chrome → Extensions → Developer Mode → Load Unpacked → choose `client-extensions/chrome`.
3. Edit `src/popup.js` and set `BACKEND_URL`.
4. Optionally enable `autoscans_enabled` in extension storage.

## Security

- Do not commit API keys.
- Restrict host_permissions before production release.

## Development

- The extension communicates with the Phisherman backend.
- Ensure the backend is running (`npm run dev` in `backend/`).
