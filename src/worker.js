/**
 * Cloudflare Worker - AI Vulnerability Scanner Backend
 *
 * This worker serves as the backend API for the vulnerability scanner.
 * It handles file uploads, orchestrates scanning, and returns results.
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { detectSQLInjection } from './agents/sql-injection-agent.js';
import { detectXSS } from './agents/xss-agent.js';
import { detectHardcodedCredentials } from './agents/credentials-agent.js';

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
  <title>SENTRI - AI Vulnerability Scanner</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');

    :root {
      --orange-400: #fb923c;
      --orange-500: #f97316;
      --orange-600: #ea580c;
      --orange-700: #c2410c;
      --black-900: #0a0a0a;
      --black-800: #111111;
      --black-700: #1a1a1a;
      --black-600: #222222;
      --black-500: #2a2a2a;
      --gray-400: #9ca3af;
      --gray-500: #6b7280;
      --gray-600: #4b5563;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--black-900);
      min-height: 100vh;
      color: #e5e5e5;
      overflow-x: hidden;
    }

    /* Animated grid background */
    .bg-grid {
      position: fixed;
      inset: 0;
      background-image:
        linear-gradient(rgba(249,115,22,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(249,115,22,0.03) 1px, transparent 1px);
      background-size: 60px 60px;
      animation: gridShift 20s linear infinite;
      z-index: 0;
    }
    @keyframes gridShift {
      0% { transform: translate(0, 0); }
      100% { transform: translate(60px, 60px); }
    }

    /* Ambient glow orbs */
    .glow-orb {
      position: fixed;
      border-radius: 50%;
      filter: blur(120px);
      opacity: 0.15;
      pointer-events: none;
      z-index: 0;
    }
    .glow-orb-1 {
      width: 600px; height: 600px;
      background: var(--orange-500);
      top: -200px; right: -100px;
      animation: orbFloat1 8s ease-in-out infinite;
    }
    .glow-orb-2 {
      width: 400px; height: 400px;
      background: var(--orange-700);
      bottom: -100px; left: -100px;
      animation: orbFloat2 10s ease-in-out infinite;
    }
    .glow-orb-3 {
      width: 300px; height: 300px;
      background: #ff6b00;
      top: 50%; left: 50%;
      transform: translate(-50%, -50%);
      animation: orbFloat3 12s ease-in-out infinite;
      opacity: 0.08;
    }
    @keyframes orbFloat1 {
      0%, 100% { transform: translate(0, 0); }
      50% { transform: translate(-40px, 30px); }
    }
    @keyframes orbFloat2 {
      0%, 100% { transform: translate(0, 0); }
      50% { transform: translate(30px, -40px); }
    }
    @keyframes orbFloat3 {
      0%, 100% { transform: translate(-50%, -50%) scale(1); }
      50% { transform: translate(-50%, -50%) scale(1.2); }
    }

    /* Layout */
    .page-wrapper {
      position: relative;
      z-index: 1;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 40px 20px;
    }

    /* Header */
    .header {
      text-align: center;
      margin-bottom: 40px;
      animation: fadeInDown 0.8s ease-out;
    }
    @keyframes fadeInDown {
      from { opacity: 0; transform: translateY(-30px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .logo {
      display: inline-flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
    }
    .logo-icon {
      width: 48px;
      height: 48px;
      background: linear-gradient(135deg, var(--orange-500) 0%, var(--orange-700) 100%);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 24px;
      box-shadow: 0 0 30px rgba(249,115,22,0.3);
      animation: logoPulse 3s ease-in-out infinite;
    }
    @keyframes logoPulse {
      0%, 100% { box-shadow: 0 0 30px rgba(249,115,22,0.3); }
      50% { box-shadow: 0 0 50px rgba(249,115,22,0.5); }
    }
    .logo-text {
      font-size: 32px;
      font-weight: 900;
      letter-spacing: 6px;
      background: linear-gradient(135deg, var(--orange-400) 0%, var(--orange-600) 50%, #fff 100%);
      background-size: 200% auto;
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      animation: shimmer 3s linear infinite;
    }
    @keyframes shimmer {
      0% { background-position: 0% center; }
      100% { background-position: 200% center; }
    }
    .tagline {
      color: var(--gray-400);
      font-size: 14px;
      font-weight: 400;
      letter-spacing: 2px;
      text-transform: uppercase;
    }

    /* Agent badges */
    .agents-bar {
      display: flex;
      gap: 10px;
      justify-content: center;
      margin-top: 16px;
      flex-wrap: wrap;
    }
    .agent-badge {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 1px;
      border: 1px solid rgba(249,115,22,0.2);
      background: rgba(249,115,22,0.05);
      color: var(--orange-400);
      animation: fadeInUp 0.8s ease-out backwards;
    }
    .agent-badge:nth-child(1) { animation-delay: 0.1s; }
    .agent-badge:nth-child(2) { animation-delay: 0.2s; }
    .agent-badge:nth-child(3) { animation-delay: 0.3s; }
    @keyframes fadeInUp {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .agent-dot {
      width: 6px; height: 6px;
      border-radius: 50%;
      background: var(--orange-500);
      animation: dotPulse 2s ease-in-out infinite;
    }
    .agent-badge:nth-child(2) .agent-dot { animation-delay: 0.3s; }
    .agent-badge:nth-child(3) .agent-dot { animation-delay: 0.6s; }
    @keyframes dotPulse {
      0%, 100% { opacity: 0.5; transform: scale(1); }
      50% { opacity: 1; transform: scale(1.3); }
    }

    /* Main card */
    .container {
      background: linear-gradient(145deg, var(--black-800) 0%, var(--black-700) 100%);
      border: 1px solid rgba(249,115,22,0.1);
      border-radius: 20px;
      padding: 36px;
      max-width: 680px;
      width: 100%;
      box-shadow:
        0 0 0 1px rgba(255,255,255,0.03),
        0 20px 60px rgba(0,0,0,0.5),
        0 0 80px rgba(249,115,22,0.05);
      animation: cardFadeIn 0.8s ease-out 0.2s backwards;
    }
    @keyframes cardFadeIn {
      from { opacity: 0; transform: translateY(20px) scale(0.98); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }

    /* Upload area */
    .upload-area {
      border: 2px dashed rgba(249,115,22,0.2);
      border-radius: 16px;
      padding: 44px 20px;
      text-align: center;
      transition: all 0.4s cubic-bezier(0.4,0,0.2,1);
      cursor: pointer;
      margin-bottom: 20px;
      position: relative;
      overflow: hidden;
      background: rgba(0,0,0,0.2);
    }
    .upload-area::before {
      content: '';
      position: absolute;
      inset: 0;
      background: radial-gradient(circle at center, rgba(249,115,22,0.05) 0%, transparent 70%);
      opacity: 0;
      transition: opacity 0.4s ease;
    }
    .upload-area:hover, .upload-area.dragover {
      border-color: var(--orange-500);
      background: rgba(249,115,22,0.04);
      box-shadow: 0 0 40px rgba(249,115,22,0.1) inset;
    }
    .upload-area:hover::before, .upload-area.dragover::before {
      opacity: 1;
    }
    .upload-icon {
      font-size: 52px;
      margin-bottom: 16px;
      filter: grayscale(0.3);
      animation: iconBounce 2s ease-in-out infinite;
    }
    @keyframes iconBounce {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-6px); }
    }
    .upload-area:hover .upload-icon { filter: grayscale(0); }
    .upload-text {
      color: #ccc;
      font-size: 15px;
      font-weight: 500;
      margin-bottom: 8px;
    }
    .upload-hint {
      color: var(--gray-500);
      font-size: 12px;
    }
    input[type="file"] { display: none; }

    /* Button */
    .btn {
      position: relative;
      background: linear-gradient(135deg, var(--orange-600) 0%, var(--orange-500) 50%, var(--orange-400) 100%);
      background-size: 200% auto;
      color: #000;
      border: none;
      padding: 16px 28px;
      border-radius: 12px;
      font-size: 15px;
      font-weight: 700;
      cursor: pointer;
      width: 100%;
      letter-spacing: 0.5px;
      transition: all 0.3s cubic-bezier(0.4,0,0.2,1);
      overflow: hidden;
      text-transform: uppercase;
    }
    .btn::before {
      content: '';
      position: absolute;
      inset: 0;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
      transform: translateX(-100%);
      transition: transform 0.6s ease;
    }
    .btn:hover {
      background-position: right center;
      transform: translateY(-2px);
      box-shadow: 0 8px 30px rgba(249,115,22,0.4), 0 0 60px rgba(249,115,22,0.15);
    }
    .btn:hover::before {
      transform: translateX(100%);
    }
    .btn:active {
      transform: translateY(0);
    }
    .btn:disabled {
      opacity: 0.35;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
    }
    .btn:disabled:hover::before {
      transform: translateX(-100%);
    }

    /* Selected file */
    .selected-file {
      background: rgba(249,115,22,0.06);
      border: 1px solid rgba(249,115,22,0.2);
      border-radius: 12px;
      padding: 14px 18px;
      margin-bottom: 20px;
      display: none;
      align-items: center;
      gap: 14px;
      animation: slideIn 0.3s ease-out;
    }
    @keyframes slideIn {
      from { opacity: 0; transform: translateX(-10px); }
      to { opacity: 1; transform: translateX(0); }
    }
    .selected-file.visible { display: flex; }
    .file-icon { font-size: 28px; }
    .file-info { flex: 1; }
    .file-name { font-weight: 600; color: var(--orange-400); font-size: 14px; }
    .file-size { font-size: 12px; color: var(--gray-500); margin-top: 2px; }

    /* Loading */
    .loading {
      text-align: center;
      padding: 40px 20px;
      display: none;
    }
    .loading.visible { display: block; }
    .scan-animation {
      position: relative;
      width: 80px;
      height: 80px;
      margin: 0 auto 24px;
    }
    .scan-ring {
      position: absolute;
      inset: 0;
      border: 3px solid rgba(249,115,22,0.1);
      border-top: 3px solid var(--orange-500);
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }
    .scan-ring:nth-child(2) {
      inset: 8px;
      border-top-color: var(--orange-400);
      animation-duration: 1.5s;
      animation-direction: reverse;
    }
    .scan-ring:nth-child(3) {
      inset: 16px;
      border-top-color: var(--orange-600);
      animation-duration: 2s;
    }
    .scan-core {
      position: absolute;
      inset: 24px;
      background: radial-gradient(circle, var(--orange-500), transparent);
      border-radius: 50%;
      animation: corePulse 1.5s ease-in-out infinite;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    @keyframes corePulse {
      0%, 100% { opacity: 0.3; transform: scale(0.8); }
      50% { opacity: 0.8; transform: scale(1.1); }
    }
    .loading-text {
      color: var(--gray-400);
      font-size: 14px;
      font-weight: 500;
    }
    .loading-sub {
      color: var(--gray-600);
      font-size: 12px;
      margin-top: 8px;
    }
    .loading-agents {
      display: flex;
      justify-content: center;
      gap: 16px;
      margin-top: 20px;
    }
    .loading-agent {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      color: var(--gray-500);
      font-weight: 500;
    }
    .loading-agent-dot {
      width: 6px; height: 6px;
      border-radius: 50%;
      background: var(--orange-500);
      animation: agentBlink 1.4s ease-in-out infinite;
    }
    .loading-agent:nth-child(2) .loading-agent-dot { animation-delay: 0.2s; }
    .loading-agent:nth-child(3) .loading-agent-dot { animation-delay: 0.4s; }
    @keyframes agentBlink {
      0%, 100% { opacity: 0.2; }
      50% { opacity: 1; }
    }

    /* Error */
    .error {
      background: rgba(220,38,38,0.08);
      border: 1px solid rgba(220,38,38,0.3);
      border-radius: 12px;
      padding: 16px 20px;
      color: #f87171;
      margin-top: 20px;
      display: none;
      font-size: 14px;
      animation: shake 0.4s ease-out;
    }
    .error.visible { display: block; }
    @keyframes shake {
      0%, 100% { transform: translateX(0); }
      20% { transform: translateX(-6px); }
      40% { transform: translateX(6px); }
      60% { transform: translateX(-4px); }
      80% { transform: translateX(4px); }
    }

    /* Results */
    .results {
      margin-top: 32px;
      display: none;
    }
    .results.visible { display: block; animation: fadeInUp 0.5s ease-out; }

    /* Summary stats */
    .summary {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: rgba(0,0,0,0.3);
      border: 1px solid rgba(255,255,255,0.05);
      border-radius: 12px;
      padding: 16px;
      text-align: center;
      transition: all 0.3s ease;
      animation: statPop 0.4s ease-out backwards;
    }
    .stat-card:nth-child(1) { animation-delay: 0.1s; }
    .stat-card:nth-child(2) { animation-delay: 0.2s; }
    .stat-card:nth-child(3) { animation-delay: 0.3s; }
    .stat-card:nth-child(4) { animation-delay: 0.4s; }
    @keyframes statPop {
      from { opacity: 0; transform: scale(0.8); }
      to { opacity: 1; transform: scale(1); }
    }
    .stat-card:hover {
      border-color: rgba(249,115,22,0.3);
      background: rgba(249,115,22,0.05);
    }
    .stat-number {
      font-size: 28px;
      font-weight: 800;
      font-family: 'JetBrains Mono', monospace;
    }
    .stat-number.critical { color: #ef4444; }
    .stat-number.high { color: var(--orange-500); }
    .stat-number.medium { color: #eab308; }
    .stat-number.low { color: #22c55e; }
    .stat-number.total {
      background: linear-gradient(135deg, var(--orange-400), var(--orange-600));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .stat-label {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 1.5px;
      color: var(--gray-500);
      margin-top: 4px;
      font-weight: 600;
    }

    /* Type breakdown bar */
    .type-breakdown {
      display: flex;
      gap: 8px;
      margin-bottom: 24px;
      flex-wrap: wrap;
    }
    .type-tag {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 6px 14px;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 600;
      border: 1px solid rgba(255,255,255,0.06);
      background: rgba(0,0,0,0.3);
    }
    .type-tag-count {
      font-family: 'JetBrains Mono', monospace;
      color: var(--orange-400);
    }
    .type-tag-label { color: var(--gray-400); }

    .results-title {
      font-size: 16px;
      font-weight: 700;
      color: #e5e5e5;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .results-title-line {
      flex: 1;
      height: 1px;
      background: linear-gradient(90deg, rgba(249,115,22,0.3), transparent);
    }

    /* Vulnerability card */
    .vulnerability {
      background: rgba(0,0,0,0.3);
      border: 1px solid rgba(255,255,255,0.05);
      border-left: 3px solid #ef4444;
      border-radius: 12px;
      padding: 18px;
      margin-bottom: 10px;
      transition: all 0.3s ease;
      animation: vulnSlideIn 0.4s ease-out backwards;
    }
    .vulnerability:hover {
      border-color: rgba(249,115,22,0.2);
      border-left-color: var(--orange-500);
      background: rgba(249,115,22,0.03);
      transform: translateX(4px);
    }
    .vulnerability.critical { border-left-color: #ef4444; }
    .vulnerability.high { border-left-color: var(--orange-500); }
    .vulnerability.medium { border-left-color: #eab308; }
    .vulnerability.low { border-left-color: #22c55e; }
    @keyframes vulnSlideIn {
      from { opacity: 0; transform: translateX(-20px); }
      to { opacity: 1; transform: translateX(0); }
    }
    .vuln-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }
    .vuln-type {
      font-weight: 600;
      font-size: 13px;
      color: #e5e5e5;
    }
    .vuln-severity {
      font-size: 10px;
      padding: 4px 10px;
      border-radius: 6px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .severity-critical {
      background: rgba(239,68,68,0.15);
      color: #f87171;
      border: 1px solid rgba(239,68,68,0.3);
    }
    .severity-high {
      background: rgba(249,115,22,0.15);
      color: var(--orange-400);
      border: 1px solid rgba(249,115,22,0.3);
    }
    .severity-medium {
      background: rgba(234,179,8,0.15);
      color: #fbbf24;
      border: 1px solid rgba(234,179,8,0.3);
    }
    .severity-low {
      background: rgba(34,197,94,0.15);
      color: #4ade80;
      border: 1px solid rgba(34,197,94,0.3);
    }
    .vuln-details { font-size: 13px; color: var(--gray-400); line-height: 1.6; }
    .vuln-line {
      font-family: 'JetBrains Mono', monospace;
      color: var(--orange-400);
      font-weight: 600;
      font-size: 12px;
    }
    .vuln-code {
      display: block;
      background: rgba(0,0,0,0.4);
      border: 1px solid rgba(255,255,255,0.04);
      border-radius: 8px;
      padding: 10px 14px;
      margin-top: 10px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      color: var(--orange-400);
      overflow-x: auto;
      white-space: pre;
    }
    .vuln-fix {
      display: flex;
      align-items: flex-start;
      gap: 6px;
      margin-top: 10px;
      padding: 10px 14px;
      background: rgba(34,197,94,0.04);
      border: 1px solid rgba(34,197,94,0.1);
      border-radius: 8px;
      font-size: 12px;
      color: #86efac;
      line-height: 1.5;
    }
    .vuln-fix-icon {
      flex-shrink: 0;
      margin-top: 1px;
    }

    /* No vulnerabilities */
    .no-vulns {
      text-align: center;
      padding: 40px 20px;
      animation: fadeInUp 0.5s ease-out;
    }
    .no-vulns-icon {
      font-size: 48px;
      margin-bottom: 12px;
      animation: checkBounce 0.6s ease-out 0.3s backwards;
    }
    @keyframes checkBounce {
      0% { opacity: 0; transform: scale(0); }
      60% { transform: scale(1.2); }
      100% { opacity: 1; transform: scale(1); }
    }
    .no-vulns-text {
      color: #4ade80;
      font-weight: 600;
      font-size: 16px;
    }
    .no-vulns-sub {
      color: var(--gray-500);
      font-size: 13px;
      margin-top: 4px;
    }

    /* Footer */
    .footer {
      margin-top: 40px;
      text-align: center;
      color: var(--gray-600);
      font-size: 12px;
      animation: fadeInUp 0.8s ease-out 0.6s backwards;
    }
    .footer a {
      color: var(--orange-500);
      text-decoration: none;
    }
    .footer a:hover { text-decoration: underline; }

    /* Responsive */
    @media (max-width: 600px) {
      .summary { grid-template-columns: repeat(2, 1fr); }
      .agents-bar { gap: 6px; }
      .agent-badge { font-size: 10px; padding: 4px 10px; }
      .container { padding: 24px; }
      .loading-agents { flex-direction: column; align-items: center; gap: 8px; }
    }
  </style>
</head>
<body>
  <div class="bg-grid"></div>
  <div class="glow-orb glow-orb-1"></div>
  <div class="glow-orb glow-orb-2"></div>
  <div class="glow-orb glow-orb-3"></div>

  <div class="page-wrapper">
    <div class="header">
      <div class="logo">
        <div class="logo-icon">&#x1f6e1;</div>
        <span class="logo-text">SENTRI</span>
      </div>
      <p class="tagline">AI-Powered Vulnerability Scanner</p>
      <div class="agents-bar">
        <div class="agent-badge"><span class="agent-dot"></span> SQL Injection</div>
        <div class="agent-badge"><span class="agent-dot"></span> XSS Detection</div>
        <div class="agent-badge"><span class="agent-dot"></span> Credentials</div>
      </div>
    </div>

    <div class="container">
      <form id="uploadForm">
        <div class="upload-area" id="dropZone">
          <div class="upload-icon">&#x1f4c2;</div>
          <p class="upload-text">Drag & drop your code file here</p>
          <p class="upload-hint">or click to browse &bull; .py .js .ts .jsx .tsx .cpp .java</p>
          <input type="file" id="fileInput" accept=".py,.js,.jsx,.ts,.tsx,.cpp,.java">
        </div>

        <div class="selected-file" id="selectedFile">
          <span class="file-icon">&#x1f4c4;</span>
          <div class="file-info">
            <div class="file-name" id="fileName"></div>
            <div class="file-size" id="fileSize"></div>
          </div>
        </div>

        <button type="submit" class="btn" id="scanBtn" disabled>Scan for Vulnerabilities</button>
      </form>

      <div class="loading" id="loading">
        <div class="scan-animation">
          <div class="scan-ring"></div>
          <div class="scan-ring"></div>
          <div class="scan-ring"></div>
          <div class="scan-core"></div>
        </div>
        <p class="loading-text">Analyzing code for vulnerabilities...</p>
        <p class="loading-sub">Running 3 AI agents in parallel</p>
        <div class="loading-agents">
          <div class="loading-agent"><span class="loading-agent-dot"></span> SQL Agent</div>
          <div class="loading-agent"><span class="loading-agent-dot"></span> XSS Agent</div>
          <div class="loading-agent"><span class="loading-agent-dot"></span> Creds Agent</div>
        </div>
      </div>

      <div class="error" id="error"></div>

      <div class="results" id="results">
        <div class="summary" id="summary"></div>
        <div class="type-breakdown" id="typeBreakdown"></div>
        <div class="results-title">
          <span>Findings</span>
          <span class="results-title-line"></span>
        </div>
        <div id="vulnerabilityList"></div>
      </div>
    </div>

    <div class="footer">
      Powered by Cloudflare Workers AI &bull; SENTRI v1.0
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
    const summary = document.getElementById('summary');
    const typeBreakdown = document.getElementById('typeBreakdown');

    let currentFile = null;

    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.classList.add('dragover');
    });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('dragover');
      if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length) handleFile(e.target.files[0]);
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
      if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
      return (bytes / 1048576).toFixed(1) + ' MB';
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
        const response = await fetch('/api/scan', { method: 'POST', body: formData });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Scan failed');
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
      summary.innerHTML = '';
      typeBreakdown.innerHTML = '';

      if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
        summary.style.display = 'none';
        typeBreakdown.style.display = 'none';
        vulnerabilityList.innerHTML =
          '<div class="no-vulns">' +
            '<div class="no-vulns-icon">&#x2705;</div>' +
            '<div class="no-vulns-text">No vulnerabilities detected</div>' +
            '<div class="no-vulns-sub">This file passed all security checks</div>' +
          '</div>';
      } else {
        summary.style.display = '';
        typeBreakdown.style.display = '';

        const s = data.summary || {};
        const bySev = s.by_severity || {};
        const byType = s.by_type || {};

        // Stats
        const stats = [
          { n: s.total || data.vulnerabilities.length, c: 'total', l: 'Total' },
          { n: bySev.critical || 0, c: 'critical', l: 'Critical' },
          { n: bySev.high || 0, c: 'high', l: 'High' },
          { n: bySev.medium || 0, c: 'medium', l: 'Medium' },
        ];
        stats.forEach(s => {
          summary.innerHTML +=
            '<div class="stat-card">' +
              '<div class="stat-number ' + s.c + '">' + s.n + '</div>' +
              '<div class="stat-label">' + s.l + '</div>' +
            '</div>';
        });

        // Type breakdown
        const types = [
          { label: 'SQL Injection', count: byType.sql_injection || 0 },
          { label: 'XSS', count: byType.xss || 0 },
          { label: 'Hard-coded Credentials', count: byType.hardcoded_credentials || 0 },
        ];
        types.filter(t => t.count > 0).forEach(t => {
          typeBreakdown.innerHTML +=
            '<div class="type-tag">' +
              '<span class="type-tag-count">' + t.count + '</span>' +
              '<span class="type-tag-label">' + t.label + '</span>' +
            '</div>';
        });

        // Vulnerability cards
        data.vulnerabilities.forEach((vuln, i) => {
          const sev = vuln.severity.toLowerCase();
          const div = document.createElement('div');
          div.className = 'vulnerability ' + sev;
          div.style.animationDelay = (i * 0.06) + 's';

          let html =
            '<div class="vuln-header">' +
              '<span class="vuln-type">' + escHtml(vuln.type) + '</span>' +
              '<span class="vuln-severity severity-' + sev + '">' + escHtml(vuln.severity) + '</span>' +
            '</div>' +
            '<div class="vuln-details">' +
              '<p><span class="vuln-line">Line ' + vuln.line + '</span> &mdash; ' + escHtml(vuln.message) + '</p>';

          if (vuln.code_snippet) {
            html += '<code class="vuln-code">' + escHtml(vuln.code_snippet) + '</code>';
          }
          if (vuln.fix_suggestion) {
            html +=
              '<div class="vuln-fix">' +
                '<span class="vuln-fix-icon">&#x1f527;</span>' +
                '<span>' + escHtml(vuln.fix_suggestion) + '</span>' +
              '</div>';
          }
          html += '</div>';
          div.innerHTML = html;
          vulnerabilityList.appendChild(div);
        });
      }
      results.classList.add('visible');
    }

    function escHtml(str) {
      const d = document.createElement('div');
      d.textContent = str || '';
      return d.innerHTML;
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

    // Run all vulnerability detection agents in parallel
    console.log('[Scan] Running SQL Injection, XSS, and Credentials detection in parallel...');
    const [sqlInjectionResults, xssResults, credentialsResults] = await Promise.all([
      detectSQLInjection(code, file.name, language, env.AI),
      detectXSS(code, file.name, language, env.AI),
      detectHardcodedCredentials(code, file.name, language, env.AI),
    ]);

    // Combine results from all agents
    const allResults = [...sqlInjectionResults, ...xssResults, ...credentialsResults];

    // Format vulnerabilities for frontend display
    const vulnerabilities = formatVulnerabilitiesForFrontend(allResults);

    // Sort by line number
    vulnerabilities.sort((a, b) => a.line - b.line);

    // Count by vulnerability type
    const sqlCount = vulnerabilities.filter((v) => v.type.includes('SQL')).length;
    const xssCount = vulnerabilities.filter((v) => v.type.includes('XSS')).length;
    const credentialsCount = vulnerabilities.filter((v) => v.type.includes('Credential')).length;

    console.log(`[Scan] Total vulnerabilities: ${vulnerabilities.length} (SQL: ${sqlCount}, XSS: ${xssCount}, Credentials: ${credentialsCount})`);

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
        by_type: {
          sql_injection: sqlCount,
          xss: xssCount,
          hardcoded_credentials: credentialsCount,
        },
        by_severity: {
          critical: vulnerabilities.filter((v) => v.severity === 'CRITICAL').length,
          high: vulnerabilities.filter((v) => v.severity === 'HIGH').length,
          medium: vulnerabilities.filter((v) => v.severity === 'MEDIUM').length,
          low: vulnerabilities.filter((v) => v.severity === 'LOW').length,
        },
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
