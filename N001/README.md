# N001 Threat Analyzer

Standalone extraction of the Nexnetra analyzer. It includes URL reputation scanning, phishing email review, and local password-strength analysis. It does not require login or PostgreSQL.

## Run locally

```bash
npm install
npm run dev
```

Open `http://127.0.0.1:5176`.

## Production build

```bash
npm run build
npm start
```

The production server runs at `http://127.0.0.1:4100` by default and serves the built frontend.

Copy `.env.example` to `.env` only when optional AI or URL-reputation provider keys are needed. Passwords are always analyzed locally and are never sent to an AI provider.
