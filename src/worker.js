/**
 * Cloudflare Worker - AI Vulnerability Scanner Backend
 *
 * This worker serves as the backend API for the vulnerability scanner.
 * It handles file uploads, orchestrates scanning, and returns results.
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { detectSQLInjection } from './agents/sql-injection-agent.js';

// Initialize Hono app
const app = new Hono();

// =============================================================================
// Configuration
// =============================================================================

const MAX_FILE_SIZE = 1 * 1024 * 1024; // 1MB limit
const ALLOWED_EXTENSIONS = ['.py', '.js', '.cpp', '.java', '.ts', '.jsx', '.tsx'];

// =============================================================================
// Middleware
// =============================================================================

// Enable CORS for frontend access
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type'],
}));

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Validates that the uploaded file has an allowed extension
 * @param {string} filename - The name of the uploaded file
 * @returns {boolean} - True if the extension is allowed
 */
function isValidFileType(filename) {
  if (!filename) return false;
  const ext = filename.toLowerCase().slice(filename.lastIndexOf('.'));
  return ALLOWED_EXTENSIONS.includes(ext);
}

/**
 * Extracts the programming language from the file extension
 * @param {string} filename - The name of the uploaded file
 * @returns {string} - The detected programming language
 */
function detectLanguage(filename) {
  const ext = filename.toLowerCase().slice(filename.lastIndexOf('.'));
  const languageMap = {
    '.py': 'python',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.cpp': 'cpp',
    '.java': 'java',
  };
  return languageMap[ext] || 'unknown';
}

/**
 * Transforms AI agent results to frontend-compatible format
 * @param {Array} agentResults - Results from AI agents
 * @returns {Array} - Formatted vulnerability array for frontend
 */
function formatVulnerabilitiesForFrontend(agentResults) {
  return agentResults.map((vuln) => ({
    type: vuln.vulnerability_type || 'Unknown',
    severity: vuln.severity || 'MEDIUM',
    line: vuln.line_number || 0,
    code_snippet: vuln.code_snippet || '',
    message: vuln.explanation ? vuln.explanation.substring(0, 100) : 'Vulnerability detected',
    explanation: vuln.explanation || '',
    fix_suggestion: vuln.fix_suggestion || '',
    confidence: vuln.confidence || 0.5,
  }));
}

// =============================================================================
// Routes
// =============================================================================

/**
 * GET / - Serve the HTML upload form
 * Simple interface for testing file uploads directly
 */
app.get('/', (c) => {
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Vulnerability Scanner</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: #fff;
      border-radius: 16px;
      padding: 40px;
      max-width: 600px;
      width: 100%;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    }
    h1 {
      color: #1a1a2e;
      margin-bottom: 8px;
      font-size: 28px;
    }
    .subtitle {
      color: #666;
      margin-bottom: 30px;
      font-size: 14px;
    }
    .upload-area {
      border: 2px dashed #ddd;
      border-radius: 12px;
      padding: 40px;
      text-align: center;
      transition: all 0.3s ease;
      cursor: pointer;
      margin-bottom: 20px;
    }
    .upload-area:hover, .upload-area.dragover {
      border-color: #4f46e5;
      background: #f8f7ff;
    }
    .upload-icon {
      font-size: 48px;
      margin-bottom: 16px;
    }
    .upload-text {
      color: #666;
      margin-bottom: 8px;
    }
    .upload-hint {
      color: #999;
      font-size: 12px;
    }
    input[type="file"] { display: none; }
    .btn {
      background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
      color: white;
      border: none;
      padding: 14px 28px;
      border-radius: 8px;
      font-size: 16px;
      cursor: pointer;
      width: 100%;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 20px rgba(79,70,229,0.4);
    }
    .btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none;
    }
    .selected-file {
      background: #f0fdf4;
      border: 1px solid #86efac;
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 20px;
      display: none;
      align-items: center;
      gap: 12px;
    }
    .selected-file.visible { display: flex; }
    .file-icon { font-size: 24px; }
    .file-info { flex: 1; }
    .file-name { font-weight: 600; color: #166534; }
    .file-size { font-size: 12px; color: #666; }
    .results {
      margin-top: 30px;
      display: none;
    }
    .results.visible { display: block; }
    .results h2 {
      color: #1a1a2e;
      margin-bottom: 16px;
      font-size: 20px;
    }
    .vulnerability {
      background: #fef2f2;
      border-left: 4px solid #ef4444;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 12px;
    }
    .vulnerability.high { border-color: #f97316; background: #fff7ed; }
    .vulnerability.medium { border-color: #eab308; background: #fefce8; }
    .vulnerability.low { border-color: #22c55e; background: #f0fdf4; }
    .vuln-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }
    .vuln-type { font-weight: 600; color: #1a1a2e; }
    .vuln-severity {
      font-size: 12px;
      padding: 4px 8px;
      border-radius: 4px;
      font-weight: 600;
    }
    .severity-critical { background: #fee2e2; color: #dc2626; }
    .severity-high { background: #ffedd5; color: #ea580c; }
    .severity-medium { background: #fef9c3; color: #ca8a04; }
    .severity-low { background: #dcfce7; color: #16a34a; }
    .vuln-details { font-size: 14px; color: #666; }
    .vuln-line { font-family: monospace; color: #4f46e5; }
    .loading {
      text-align: center;
      padding: 20px;
      display: none;
    }
    .loading.visible { display: block; }
    .spinner {
      border: 3px solid #f3f3f3;
      border-top: 3px solid #4f46e5;
      border-radius: 50%;
      width: 40px;
      height: 40px;
      animation: spin 1s linear infinite;
      margin: 0 auto 16px;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    .error {
      background: #fef2f2;
      border: 1px solid #fecaca;
      border-radius: 8px;
      padding: 16px;
      color: #dc2626;
      margin-top: 20px;
      display: none;
    }
    .error.visible { display: block; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔒 AI Vulnerability Scanner</h1>
    <p class="subtitle">Upload your code files to scan for security vulnerabilities</p>

    <form id="uploadForm">
      <div class="upload-area" id="dropZone">
        <div class="upload-icon">📁</div>
        <p class="upload-text">Drag & drop your code file here</p>
        <p class="upload-hint">or click to browse • Supports .py, .js, .cpp, .java files</p>
        <input type="file" id="fileInput" accept=".py,.js,.jsx,.ts,.tsx,.cpp,.java">
      </div>

      <div class="selected-file" id="selectedFile">
        <span class="file-icon">📄</span>
        <div class="file-info">
          <div class="file-name" id="fileName"></div>
          <div class="file-size" id="fileSize"></div>
        </div>
      </div>

      <button type="submit" class="btn" id="scanBtn" disabled>Scan for Vulnerabilities</button>
    </form>

    <div class="loading" id="loading">
      <div class="spinner"></div>
      <p>Analyzing code for vulnerabilities...</p>
    </div>

    <div class="error" id="error"></div>

    <div class="results" id="results">
      <h2>Scan Results</h2>
      <div id="vulnerabilityList"></div>
    </div>
  </div>

  <script>
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const selectedFile = document.getElementById('selectedFile');
    const fileName = document.getElementById('fileName');
    const fileSize = document.getElementById('fileSize');
    const scanBtn = document.getElementById('scanBtn');
    const uploadForm = document.getElementById('uploadForm');
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    const vulnerabilityList = document.getElementById('vulnerabilityList');
    const errorDiv = document.getElementById('error');

    let currentFile = null;

    // Drag and drop handlers
    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.classList.add('dragover');
    });
    dropZone.addEventListener('dragleave', () => {
      dropZone.classList.remove('dragover');
    });
    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('dragover');
      if (e.dataTransfer.files.length) {
        handleFile(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length) {
        handleFile(e.target.files[0]);
      }
    });

    function handleFile(file) {
      currentFile = file;
      fileName.textContent = file.name;
      fileSize.textContent = formatFileSize(file.size);
      selectedFile.classList.add('visible');
      scanBtn.disabled = false;
      results.classList.remove('visible');
      errorDiv.classList.remove('visible');
    }

    function formatFileSize(bytes) {
      if (bytes < 1024) return bytes + ' B';
      if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
      return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    uploadForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!currentFile) return;

      loading.classList.add('visible');
      results.classList.remove('visible');
      errorDiv.classList.remove('visible');
      scanBtn.disabled = true;

      const formData = new FormData();
      formData.append('file', currentFile);

      try {
        const response = await fetch('/api/scan', {
          method: 'POST',
          body: formData
        });

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.error || 'Scan failed');
        }

        displayResults(data);
      } catch (err) {
        errorDiv.textContent = err.message;
        errorDiv.classList.add('visible');
      } finally {
        loading.classList.remove('visible');
        scanBtn.disabled = false;
      }
    });

    function displayResults(data) {
      vulnerabilityList.innerHTML = '';

      if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
        vulnerabilityList.innerHTML = '<p style="color: #16a34a; text-align: center; padding: 20px;">✅ No vulnerabilities found!</p>';
      } else {
        data.vulnerabilities.forEach(vuln => {
          const severityClass = vuln.severity.toLowerCase();
          const div = document.createElement('div');
          div.className = 'vulnerability ' + severityClass;
          div.innerHTML = \`
            <div class="vuln-header">
              <span class="vuln-type">\${vuln.type}</span>
              <span class="vuln-severity severity-\${severityClass}">\${vuln.severity}</span>
            </div>
            <div class="vuln-details">
              <p><span class="vuln-line">Line \${vuln.line}</span> - \${vuln.message}</p>
              \${vuln.explanation ? '<p style="margin-top: 8px;"><strong>Explanation:</strong> ' + vuln.explanation + '</p>' : ''}
              \${vuln.fix_suggestion ? '<p style="margin-top: 8px;"><strong>Fix:</strong> ' + vuln.fix_suggestion + '</p>' : ''}
            </div>
          \`;
          vulnerabilityList.appendChild(div);
        });
      }

      results.classList.add('visible');
    }
  </script>
</body>
</html>
  `;
  return c.html(html);
});

/**
 * GET /api/health - Health check endpoint
 * Returns status "ok" to verify the worker is running
 */
app.get('/api/health', (c) => {
  return c.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
  });
});

/**
 * POST /api/debug-scan - Debug endpoint to see raw AI responses
 * Use this to troubleshoot scanning issues
 */
app.post('/api/debug-scan', async (c) => {
  try {
    const { env } = c.env;

    // Debug environment
    console.log('[Debug] c.env keys:', Object.keys(c.env));
    console.log('[Debug] env exists:', !!env);
    console.log('[Debug] env keys:', env ? Object.keys(env) : 'null');
    console.log('[Debug] env.AI exists:', !!env?.AI);

    const formData = await c.req.formData();
    const file = formData.get('file');

    if (!file) {
      return c.json({ error: 'No file uploaded' }, 400);
    }

    const content = await file.text();
    const language = detectLanguage(file.name);

    return c.json({
      debug: true,
      filename: file.name,
      language: language,
      content_length: content.length,
      content_preview: content.substring(0, 500),
      env_keys: env ? Object.keys(env) : [],
      ai_binding_exists: !!env?.AI,
      c_env_keys: Object.keys(c.env),
    });
  } catch (error) {
    return c.json({
      error: error.message,
      stack: error.stack,
    }, 500);
  }
});

/**
 * POST /api/scan - File upload and scanning endpoint
 * Accepts code files and returns vulnerability analysis using AI
 */
app.post('/api/scan', async (c) => {
  try {
    // Get environment bindings from context
    const { env } = c.env;

    // Debug logging for environment
    console.log('[Scan] Environment check:');
    console.log('[Scan]   c.env keys:', Object.keys(c.env));
    console.log('[Scan]   env exists:', !!env);
    console.log('[Scan]   env.AI exists:', !!env?.AI);

    // Parse the multipart form data
    const formData = await c.req.formData();
    const file = formData.get('file');

    // Validate file exists
    if (!file || !(file instanceof File)) {
      return c.json(
        { error: 'No file uploaded. Please select a code file to scan.' },
        400
      );
    }

    // Validate file type
    if (!isValidFileType(file.name)) {
      return c.json(
        {
          error: `Invalid file type. Allowed types: ${ALLOWED_EXTENSIONS.join(', ')}`,
        },
        400
      );
    }

    // Validate file size
    if (file.size > MAX_FILE_SIZE) {
      return c.json(
        {
          error: `File too large. Maximum size is ${MAX_FILE_SIZE / 1024 / 1024}MB`,
        },
        400
      );
    }

    // Read file content
    const code = await file.text();
    const language = detectLanguage(file.name);

    // Run SQL injection detection using Workers AI
    const sqlInjectionResults = await detectSQLInjection(
      code,
      file.name,
      language,
      env.AI
    );

    // Format vulnerabilities for frontend display
    const vulnerabilities = formatVulnerabilitiesForFrontend(sqlInjectionResults);

    // Return scan results
    return c.json({
      status: 'success',
      filename: file.name,
      language: language,
      lines_scanned: code.split('\n').length,
      scan_timestamp: new Date().toISOString(),
      vulnerabilities: vulnerabilities,
      summary: {
        total: vulnerabilities.length,
        critical: vulnerabilities.filter((v) => v.severity === 'CRITICAL').length,
        high: vulnerabilities.filter((v) => v.severity === 'HIGH').length,
        medium: vulnerabilities.filter((v) => v.severity === 'MEDIUM').length,
        low: vulnerabilities.filter((v) => v.severity === 'LOW').length,
      },
    });
  } catch (error) {
    console.error('Scan error:', error);
    return c.json(
      { error: 'An error occurred while processing the file. Please try again.' },
      500
    );
  }
});

// =============================================================================
// Export Worker
// =============================================================================

/**
 * Main worker export
 * The env parameter includes bindings like env.AI for Workers AI
 */
export default {
  async fetch(request, env, ctx) {
    // Store env in app context for use in route handlers
    // This allows access to env.AI for AI calls in future implementations
    return app.fetch(request, { env, ctx });
  },
};
