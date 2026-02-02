# Testing Guide for AI Vulnerability Scanner

This document explains how to test the SQL Injection vulnerability scanner.

## Prerequisites

1. **Node.js 18+** - Required for native `fetch` and `FormData` support
2. **Cloudflare account** - Required for Workers AI access
3. **Wrangler CLI** - Installed via `npm install`

## Quick Start

```bash
# Install dependencies
npm install

# Start the dev server with remote AI access
npm run dev:remote

# In a new terminal, run the tests
npm test
```

## Starting the Development Server

### Local Mode (No AI)
```bash
npm run dev
```
This starts the server at `http://localhost:8787` but AI calls will fail since Workers AI requires remote access.

### Remote Mode (With AI) - Recommended for Testing
```bash
npm run dev:remote
# or
wrangler dev --remote
```
This connects to Cloudflare's network, enabling Workers AI functionality.

## Manual Testing via Web Interface

1. Start the dev server: `npm run dev:remote`
2. Open `http://localhost:8787` in your browser
3. You'll see a drag-and-drop file upload interface
4. Upload any of the test files from `test-samples/`:
   - `vulnerable-sql.py` - Should detect 4 SQL injection vulnerabilities
   - `vulnerable-sql.js` - Should detect 3 SQL injection vulnerabilities
   - `safe-sql.py` - Should detect 0 vulnerabilities
5. View the results displayed on the page

## Automated Testing

Run the automated test suite:

```bash
npm test
```

This executes `test-scanner.js` which:
1. Checks if the dev server is running
2. Uploads each test file to the `/api/scan` endpoint
3. Displays detected vulnerabilities with severity and line numbers
4. Shows a summary of test results

### Expected Output

```
╔══════════════════════════════════════════════════════════════════╗
║           SQL Injection Scanner - Test Suite                     ║
╚══════════════════════════════════════════════════════════════════╝

Checking if dev server is running...
Server is running!

Expected: 4 vulnerabilities
Description: Python SQL injection vulnerabilities

======================================================================
Testing: vulnerable-sql.py
======================================================================
...
```

## Test Files

### test-samples/vulnerable-sql.py
Contains 4 SQL injection vulnerabilities:

| Line | Vulnerability Type | Description |
|------|-------------------|-------------|
| 7 | String Concatenation | `"SELECT * FROM users WHERE id = '" + user_id + "'"` |
| 15 | F-String | `f"SELECT * FROM users WHERE username = '{username}'"` |
| 23 | String Concatenation | `"SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"` |
| 31 | Format Method | `"SELECT * FROM orders WHERE order_id = {}".format(order_id)` |

### test-samples/vulnerable-sql.js
Contains 3 SQL injection vulnerabilities:

| Line | Vulnerability Type | Description |
|------|-------------------|-------------|
| 12 | String Concatenation | `"SELECT * FROM users WHERE id = '" + userId + "'"` |
| 26 | Template Literal | `` `SELECT * FROM users WHERE username = '${username}'` `` |
| 34 | String Concatenation | `"SELECT * FROM users WHERE name LIKE '%" + searchTerm + "%'"` |

### test-samples/safe-sql.py
Contains 0 vulnerabilities - uses parameterized queries:
- `cursor.execute(query, (user_id,))` - Positional parameters
- `cursor.execute(query, {"username": username})` - Named parameters

## Success Criteria

| Test File | Expected Detections | Pass Threshold |
|-----------|--------------------:|---------------:|
| vulnerable-sql.py | 4 | 80% (3+) |
| vulnerable-sql.js | 3 | 80% (2+) |
| safe-sql.py | 0 | 0 false positives |

## API Endpoints

### Health Check
```bash
curl http://localhost:8787/api/health
```
Expected response:
```json
{"status": "ok", "timestamp": "...", "version": "1.0.0"}
```

### Scan Endpoint
```bash
curl -X POST http://localhost:8787/api/scan \
  -F "file=@test-samples/vulnerable-sql.py"
```
Expected response:
```json
{
  "status": "success",
  "filename": "vulnerable-sql.py",
  "language": "python",
  "lines_scanned": 33,
  "scan_timestamp": "...",
  "vulnerabilities": [...],
  "summary": {
    "total": 4,
    "critical": 2,
    "high": 2,
    "medium": 0,
    "low": 0
  }
}
```

## Troubleshooting

### "AI binding not available"
- Make sure you're running with `--remote` flag: `npm run dev:remote`
- Verify `wrangler.toml` has `[ai]` binding configured

### "Server is not running"
- Start the dev server first: `npm run dev:remote`
- Check if port 8787 is available

### Low Detection Rate
- The AI model may occasionally miss some vulnerabilities
- Re-run the test - AI responses can vary slightly
- Check the console logs for any parsing errors

### JSON Parse Errors
- The AI sometimes returns malformed JSON
- The agent includes error handling for this
- Check server logs for detailed error messages

## Adding New Test Cases

1. Create a new file in `test-samples/`
2. Add the test case to `test-scanner.js`:
```javascript
const testCases = [
  // ... existing cases
  {
    file: 'your-new-file.py',
    description: 'Description of what it tests',
    expectedVulnerabilities: 3,
  },
];
```
3. Run `npm test` to verify
