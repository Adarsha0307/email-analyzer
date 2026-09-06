# Email + URL Analyzer

A standalone cybersecurity analyzer for reviewing suspicious email content, URLs, and password strength. The application runs without login or PostgreSQL and includes local fallback analysis when optional API keys are not configured.

## Features

- Detects phishing language, urgency, impersonation, suspicious links, and financial bait in emails
- Scans URLs using DNS, SSL/TLS, redirect, reputation, brand-impersonation, and structural checks
- Audits password length, complexity, repetition, and common weak patterns
- Blocks private and local network URLs to reduce SSRF risk
- Uses an in-memory URL scan cache
- Provides a responsive React interface
- Keeps password analysis local and never sends passwords to AI providers

## Technology

- React 18
- Vite 6
- Node.js 20+
- Express 5

## Installation

Clone the repository and enter the application directory:

```bash
git clone https://github.com/Adarsha0307/email-analyzer.git
cd email-analyzer/N001
npm ci
```

## Run Locally

Start the frontend and backend together:

```bash
npm run dev
```

Open the application at:

```text
http://127.0.0.1:5176
```

The development backend runs at `http://127.0.0.1:4100`.

## Production

Build the frontend and start the production server:

```bash
npm run build
npm start
```

Open `http://127.0.0.1:4100` after the server starts.

## Optional Configuration

The analyzer works without API keys by using local detection rules. To enable AI-assisted email analysis or additional URL-reputation providers, create an environment file:

```powershell
Copy-Item .env.example .env
```

Available optional variables include:

```env
OPENROUTER_API_KEY=
OPENROUTER_MODEL=openai/gpt-4o-mini
GEMINI_API_KEY=
GEMINI_MODEL=gemini-1.5-flash
GOOGLE_SAFE_BROWSING_KEY=
VIRUSTOTAL_API_KEY=
PHISHTANK_API_KEY=
ABUSEIPDB_API_KEY=
```

Never commit the `.env` file or real API keys.

## API Endpoints

- `GET /api/health`
- `POST /api/analyze/email` with `{ "text": "..." }`
- `POST /api/analyze/url` with `{ "url": "..." }`
- `POST /api/analyze/password` with `{ "password": "..." }`

## Project Location

The application source is contained in the `N001` directory:

```text
N001/
|-- server/        Backend API and analyzer services
|-- src/           React frontend
|-- .env.example   Optional configuration template
|-- package.json   Scripts and dependencies
`-- vite.config.js Development server configuration
```

## Security Notice

Analyzer results are advisory and should not replace professional incident response or a dedicated malware-analysis environment. Do not open suspicious links or attachments while investigating them.
