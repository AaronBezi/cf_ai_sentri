/**
 * SQL Injection Scanner Test Script
 *
 * This script tests the vulnerability scanner against sample files
 * to verify detection accuracy.
 *
 * Usage: node test-scanner.js
 * Note: Requires the dev server running at http://localhost:8787
 */

const fs = require('fs');
const path = require('path');

// ANSI color codes for terminal output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
};

const API_URL = 'http://localhost:8787/api/scan';

/**
 * Get severity color based on level
 */
function getSeverityColor(severity) {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL':
      return colors.red;
    case 'HIGH':
      return colors.magenta;
    case 'MEDIUM':
      return colors.yellow;
    case 'LOW':
      return colors.green;
    default:
      return colors.reset;
  }
}

/**
 * Test a single file against the scanner API
 */
async function testScanner(filename) {
  console.log(`\n${colors.cyan}${'='.repeat(70)}${colors.reset}`);
  console.log(`${colors.bright}Testing: ${filename}${colors.reset}`);
  console.log(`${colors.cyan}${'='.repeat(70)}${colors.reset}`);

  const filepath = path.join(__dirname, 'test-samples', filename);

  // Check if file exists
  if (!fs.existsSync(filepath)) {
    console.log(`${colors.red}Error: File not found: ${filepath}${colors.reset}`);
    return { filename, success: false, error: 'File not found' };
  }

  const content = fs.readFileSync(filepath, 'utf8');
  console.log(`File size: ${content.length} bytes, ${content.split('\n').length} lines\n`);

  // Create form data with the file
  const formData = new FormData();
  const blob = new Blob([content], { type: 'text/plain' });
  formData.append('file', blob, filename);

  try {
    const startTime = Date.now();
    const response = await fetch(API_URL, {
      method: 'POST',
      body: formData,
    });

    const elapsed = Date.now() - startTime;
    const result = await response.json();

    if (!response.ok) {
      console.log(`${colors.red}Error: ${result.error}${colors.reset}`);
      return { filename, success: false, error: result.error };
    }

    console.log(`${colors.green}Status: ${result.status}${colors.reset}`);
    console.log(`Language: ${result.language}`);
    console.log(`Scan time: ${elapsed}ms`);
    console.log(
      `${colors.bright}Vulnerabilities found: ${result.vulnerabilities?.length || 0}${colors.reset}\n`
    );

    // Display summary
    if (result.summary) {
      console.log('Summary:');
      console.log(`  ${colors.red}Critical: ${result.summary.critical}${colors.reset}`);
      console.log(`  ${colors.magenta}High: ${result.summary.high}${colors.reset}`);
      console.log(`  ${colors.yellow}Medium: ${result.summary.medium}${colors.reset}`);
      console.log(`  ${colors.green}Low: ${result.summary.low}${colors.reset}\n`);
    }

    // Display each vulnerability
    if (result.vulnerabilities && result.vulnerabilities.length > 0) {
      result.vulnerabilities.forEach((vuln, index) => {
        const severityColor = getSeverityColor(vuln.severity);
        console.log(
          `${colors.bright}[${index + 1}]${colors.reset} ${vuln.type || vuln.vulnerability_type} - ${severityColor}${vuln.severity}${colors.reset}`
        );
        console.log(`    ${colors.blue}Line ${vuln.line || vuln.line_number}:${colors.reset} ${vuln.code_snippet || 'N/A'}`);
        console.log(`    ${colors.cyan}Issue:${colors.reset} ${vuln.explanation || vuln.message || 'N/A'}`);
        if (vuln.fix_suggestion) {
          console.log(`    ${colors.green}Fix:${colors.reset} ${vuln.fix_suggestion}`);
        }
        if (vuln.confidence !== undefined) {
          console.log(`    Confidence: ${(vuln.confidence * 100).toFixed(0)}%`);
        }
        console.log('');
      });
    } else {
      console.log(`${colors.green}No vulnerabilities detected in this file.${colors.reset}\n`);
    }

    return {
      filename,
      success: true,
      vulnerabilities: result.vulnerabilities?.length || 0,
      elapsed,
    };
  } catch (error) {
    console.log(`${colors.red}Error testing scanner: ${error.message}${colors.reset}`);
    return { filename, success: false, error: error.message };
  }
}

/**
 * Check if the server is running
 */
async function checkServer() {
  try {
    const response = await fetch('http://localhost:8787/api/health');
    const data = await response.json();
    return data.status === 'ok';
  } catch {
    return false;
  }
}

/**
 * Run all tests
 */
async function runAllTests() {
  console.log(`${colors.bright}${colors.cyan}`);
  console.log('╔══════════════════════════════════════════════════════════════════╗');
  console.log('║           SQL Injection Scanner - Test Suite                     ║');
  console.log('╚══════════════════════════════════════════════════════════════════╝');
  console.log(`${colors.reset}`);

  // Check if server is running
  console.log('Checking if dev server is running...');
  const serverUp = await checkServer();

  if (!serverUp) {
    console.log(`\n${colors.red}Error: Dev server is not running!${colors.reset}`);
    console.log(`\nPlease start the server first with: ${colors.cyan}npm run dev${colors.reset}`);
    console.log('Or for remote AI access: wrangler dev --remote\n');
    process.exit(1);
  }

  console.log(`${colors.green}Server is running!${colors.reset}\n`);

  // Test files and expected results
  const testCases = [
    {
      file: 'vulnerable-sql.py',
      description: 'Python SQL injection vulnerabilities',
      expectedVulnerabilities: 4,
    },
    {
      file: 'vulnerable-sql.js',
      description: 'JavaScript SQL injection vulnerabilities',
      expectedVulnerabilities: 3,
    },
    {
      file: 'safe-sql.py',
      description: 'Safe Python code with parameterized queries',
      expectedVulnerabilities: 0,
    },
  ];

  const results = [];

  for (const testCase of testCases) {
    console.log(`\n${colors.yellow}Expected: ${testCase.expectedVulnerabilities} vulnerabilities${colors.reset}`);
    console.log(`${colors.yellow}Description: ${testCase.description}${colors.reset}`);

    const result = await testScanner(testCase.file);
    result.expected = testCase.expectedVulnerabilities;
    results.push(result);
  }

  // Print summary
  console.log(`\n${colors.cyan}${'='.repeat(70)}${colors.reset}`);
  console.log(`${colors.bright}TEST SUMMARY${colors.reset}`);
  console.log(`${colors.cyan}${'='.repeat(70)}${colors.reset}\n`);

  let passed = 0;
  let failed = 0;

  results.forEach((result) => {
    const statusIcon = result.success ? '✓' : '✗';
    const statusColor = result.success ? colors.green : colors.red;

    let detectionStatus = '';
    if (result.success) {
      const detected = result.vulnerabilities;
      const expected = result.expected;

      if (expected === 0) {
        // For safe files, we want 0 or very few false positives
        if (detected === 0) {
          detectionStatus = `${colors.green}(No false positives)${colors.reset}`;
          passed++;
        } else {
          detectionStatus = `${colors.yellow}(${detected} false positives)${colors.reset}`;
          failed++;
        }
      } else {
        // For vulnerable files, check detection rate
        const rate = ((detected / expected) * 100).toFixed(0);
        if (detected >= expected * 0.8) {
          detectionStatus = `${colors.green}(${detected}/${expected} - ${rate}% detected)${colors.reset}`;
          passed++;
        } else {
          detectionStatus = `${colors.yellow}(${detected}/${expected} - ${rate}% detected)${colors.reset}`;
          failed++;
        }
      }
    } else {
      detectionStatus = `${colors.red}(Error: ${result.error})${colors.reset}`;
      failed++;
    }

    console.log(`${statusColor}${statusIcon}${colors.reset} ${result.filename} ${detectionStatus}`);
  });

  console.log(`\n${colors.bright}Results: ${passed} passed, ${failed} failed${colors.reset}`);

  if (failed === 0) {
    console.log(`\n${colors.green}All tests passed! The scanner is working correctly.${colors.reset}\n`);
  } else {
    console.log(`\n${colors.yellow}Some tests need attention. Review the results above.${colors.reset}\n`);
  }
}

// Run the tests
runAllTests().catch(console.error);
