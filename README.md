# SENTRI - AI-Powered Vulnerability Scanner

SENTRI is a code vulnerability scanner built on Cloudflare Workers that uses Llama 3.3 (via Workers AI) to detect security issues in source code. It runs three specialized AI agents in parallel to scan for SQL injection, XSS, and hardcoded credentials, and includes a chat interface for follow-up questions about findings.

## Features

- **Multi-Agent Scanning** - Three AI agents run in parallel to detect SQL injection, XSS vulnerabilities, and hardcoded credentials
- **Chat Interface** - Ask follow-up questions about scan results and get detailed fix suggestions powered by Llama 3.3
- **Scan History** - Past scans and chat conversations are persisted to Cloudflare KV and accessible via a slide-out sidebar
- **Session Management** - Client-side session tracking so scan history persists across page reloads
- **Drag-and-Drop Upload** - Upload code files via drag-and-drop or file browser
- **Multi-Language Support** - Scans Python, JavaScript, TypeScript, Java, and C++ files

## Architecture

| Component | Technology |
|---|---|
| Runtime | Cloudflare Workers |
| LLM | Meta Llama 3.3-70b-instruct via Workers AI |
| Web Framework | Hono |
| Storage | Cloudflare KV |
| Frontend | Embedded HTML/CSS/JS served from the Worker |

### How It Works

1. User uploads a code file through the web UI
2. The Worker runs three AI agents in parallel using `Promise.all`:
   - `sql-injection-agent.js` - Detects SQL injection patterns
   - `xss-agent.js` - Detects cross-site scripting vulnerabilities
   - `credentials-agent.js` - Detects hardcoded secrets, API keys, and passwords
3. Results are aggregated, sorted by line number, and displayed with severity ratings
4. Scan results are persisted to KV storage
5. Users can ask follow-up questions via the chat panel, which sends the code and findings as context to the LLM

### API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Serves the web UI |
| `GET` | `/api/health` | Health check |
| `POST` | `/api/scan` | Upload and scan a code file |
| `POST` | `/api/chat` | Chat about scan results (requires `X-Session-Id` header) |
| `GET` | `/api/scans` | List scan history for the current session |
| `GET` | `/api/scans/:scanId` | Get a specific past scan with chat history |

## Project Structure

```
src/
  worker.js                  # Main Worker, routes, and embedded frontend
  agents/
    sql-injection-agent.js   # SQL injection detection agent
    xss-agent.js             # XSS detection agent
    credentials-agent.js     # Hardcoded credentials detection agent
test-samples/                # Sample files for testing detection
wrangler.toml                # Cloudflare Workers configuration
test-scanner.js              # Automated test suite
```

## Setup

### Prerequisites

- Node.js 18+
- A Cloudflare account
- Wrangler CLI (`npm install -g wrangler`)

### Installation

```bash
git clone https://github.com/AaronBezi/cf_ai_sentri.git
cd cf_ai_sentri
npm install
```

### Configure KV Storage

Create the KV namespace for scan history and chat persistence:

```bash
wrangler kv namespace create "SCAN_HISTORY"
```

Copy the returned `id` into `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "SCAN_HISTORY"
id = "<your-namespace-id>"
preview_id = "<your-namespace-id>"
```

### Development

```bash
# Local development (no AI - agents will fail)
npm run dev

# Development with remote Workers AI access
npm run dev:remote
```

The app will be available at `http://localhost:8787`.

### Deploy

```bash
npm run deploy
```

### Testing

With the dev server running:

```bash
npm test
```

This runs 9 test cases across all three vulnerability types, checking detection rates against known vulnerable and safe sample files.

## Supported File Types

`.py`, `.js`, `.jsx`, `.ts`, `.tsx`, `.cpp`, `.java`