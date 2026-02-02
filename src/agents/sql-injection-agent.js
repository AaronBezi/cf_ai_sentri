/**
 * SQL Injection Vulnerability Detection Agent
 *
 * Uses Cloudflare Workers AI (Llama 3.3) to analyze code
 * for SQL injection vulnerabilities.
 */

// The model to use for SQL injection detection
const MODEL = '@cf/meta/llama-3.3-70b-instruct-fp8-fast';

/**
 * Adds line numbers to code for accurate line tracking
 * @param {string} code - Source code
 * @returns {string} - Code with line numbers prefixed
 */
function addLineNumbers(code) {
  return code
    .split('\n')
    .map((line, index) => `${index + 1}: ${line}`)
    .join('\n');
}

/**
 * Constructs an explicit, detailed prompt for the AI model
 * Line numbers are added to the code to ensure accurate reporting
 * @param {string} code - Source code to analyze
 * @param {string} language - Programming language
 * @returns {string} - The formatted prompt
 */
function buildPrompt(code, language) {
  // Add explicit line numbers to the code
  const numberedCode = addLineNumbers(code);
  const totalLines = code.split('\n').length;

  return `You are an expert security researcher specializing in SQL injection vulnerabilities.

CRITICAL REQUIREMENTS - READ CAREFULLY:
1. You MUST analyze the ENTIRE code file from line 1 to line ${totalLines}
2. You MUST find ALL SQL injection vulnerabilities, not just the first few
3. Do NOT stop scanning after finding 2-3 vulnerabilities - continue to the END
4. EVERY function in the code must be analyzed completely
5. Check EVERY line that contains SQL-related keywords (SELECT, INSERT, UPDATE, DELETE, query, execute)

TASK: Find ALL SQL injection vulnerabilities in this ${language} code (${totalLines} lines total).

CODE TO ANALYZE (line numbers shown before each line):
\`\`\`${language}
${numberedCode}
\`\`\`

SQL INJECTION PATTERNS TO DETECT - Check for ALL of these:

Pattern 1: String concatenation with + operator
   VULNERABLE: query = "SELECT * FROM users WHERE id = '" + user_id + "'"

Pattern 2: F-strings with variables (Python f"...")
   VULNERABLE: query = f"SELECT * FROM users WHERE id = '{user_id}'"

Pattern 3: .format() method
   VULNERABLE: query = "SELECT * FROM users WHERE id = {}".format(user_id)

Pattern 4: Template literals with \${} (JavaScript)
   VULNERABLE: query = \`SELECT * FROM users WHERE id = '\${userId}'\`

Pattern 5: Percent % operator formatting
   VULNERABLE: query = "SELECT * FROM users WHERE id = '%s'" % user_id

Pattern 6: String concatenation in LIKE clauses
   VULNERABLE: query = "SELECT * FROM products WHERE name LIKE '%" + search + "%'"

SAFE CODE (these are NOT vulnerabilities):
   SAFE: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
   SAFE: cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})

ANALYSIS CHECKLIST - You must check ALL of these:
[ ] Line 1-10: Check for vulnerabilities
[ ] Line 11-20: Check for vulnerabilities
[ ] Line 21-30: Check for vulnerabilities
[ ] Line 31-${totalLines}: Check for vulnerabilities
[ ] All functions analyzed

For EACH vulnerability found, report:
- vulnerability_type: "SQL Injection"
- severity: "CRITICAL" (for direct string manipulation in SQL)
- line_number: The EXACT number shown at the start of the line (before the colon)
- code_snippet: The vulnerable code (without the line number prefix)
- explanation: Why this is vulnerable
- fix_suggestion: How to fix with parameterized queries
- confidence: 0.95

RESPONSE FORMAT - Return ONLY a compact JSON array on a single line if possible:
[{"vulnerability_type":"SQL Injection","severity":"CRITICAL","line_number":7,"code_snippet":"query = ...","explanation":"Direct SQL concatenation","fix_suggestion":"Use parameterized query","confidence":0.95},{"vulnerability_type":"SQL Injection","severity":"CRITICAL","line_number":15,"code_snippet":"query = ...","explanation":"F-string in SQL","fix_suggestion":"Use parameterized query","confidence":0.95}]

CRITICAL FINAL REQUIREMENTS:
- Return ALL vulnerabilities (if 4 exist, return all 4)
- Start response with [ and end with ]
- NO markdown, NO code blocks, NO explanations
- Keep explanations SHORT to fit all vulnerabilities
- Use exact line numbers from the numbered code

JSON ARRAY OUTPUT:`;
}

/**
 * Extracts and repairs JSON from AI response text
 * Handles truncated responses, markdown formatting, and malformed JSON
 * @param {string} text - Raw AI response text
 * @returns {Array} - Parsed vulnerability array
 */
function extractAndParseJSON(text) {
  if (!text) {
    console.log('[SQL Agent] Empty response text');
    return [];
  }

  let cleaned = text.trim();

  // Log the COMPLETE response for debugging
  console.log('[SQL Agent] ===== COMPLETE AI RESPONSE =====');
  console.log(cleaned);
  console.log('[SQL Agent] ===== END RESPONSE =====');
  console.log('[SQL Agent] Response length:', cleaned.length, 'characters');

  // Check which line numbers are mentioned in the response
  const checkLines = [7, 15, 23, 31];
  checkLines.forEach((line) => {
    const found =
      cleaned.includes(`"line_number": ${line}`) ||
      cleaned.includes(`"line_number":${line}`) ||
      cleaned.includes(`"line_number" : ${line}`);
    console.log(`[SQL Agent] Response mentions line ${line}:`, found);
  });

  // Remove markdown code blocks if present
  const codeBlockMatch = cleaned.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (codeBlockMatch) {
    console.log('[SQL Agent] Extracted content from markdown code block');
    cleaned = codeBlockMatch[1].trim();
  }

  // Find where the JSON array starts
  const arrayStart = cleaned.indexOf('[');
  if (arrayStart === -1) {
    console.log('[SQL Agent] No JSON array found in response');
    return [];
  }

  cleaned = cleaned.substring(arrayStart);

  // Try to parse as-is first
  try {
    const parsed = JSON.parse(cleaned);
    if (Array.isArray(parsed)) {
      console.log(`[SQL Agent] Successfully parsed ${parsed.length} vulnerabilities directly`);
      return parsed.filter(isValidVulnerability).map(normalizeVulnerability);
    }
  } catch (e) {
    console.log('[SQL Agent] Direct parse failed:', e.message);
  }

  // If the array is incomplete (no closing bracket), try to repair it
  if (!cleaned.trim().endsWith(']')) {
    console.log('[SQL Agent] JSON array appears truncated, attempting repair...');

    // Find the last complete object (ends with })
    const lastBrace = cleaned.lastIndexOf('}');
    if (lastBrace > 0) {
      const repaired = cleaned.substring(0, lastBrace + 1) + '\n]';
      console.log('[SQL Agent] Attempting to parse repaired JSON (added closing bracket)');
      try {
        const parsed = JSON.parse(repaired);
        if (Array.isArray(parsed)) {
          console.log(`[SQL Agent] Repaired JSON: found ${parsed.length} vulnerabilities`);
          return parsed.filter(isValidVulnerability).map(normalizeVulnerability);
        }
      } catch (e) {
        console.log('[SQL Agent] Repaired JSON parse failed:', e.message);
      }
    }
  }

  // First, count how many line numbers are mentioned in the response
  const lineNumberPattern = /"line_number"\s*:\s*(\d+)/g;
  const foundLineNumbers = [];
  let lineMatch;

  while ((lineMatch = lineNumberPattern.exec(cleaned)) !== null) {
    const lineNum = parseInt(lineMatch[1], 10);
    if (!foundLineNumbers.includes(lineNum)) {
      foundLineNumbers.push(lineNum);
    }
  }

  console.log('[SQL Agent] Line numbers found in response:', foundLineNumbers);
  console.log('[SQL Agent] Expected vulnerabilities:', foundLineNumbers.length);

  // Try regex extraction for individual objects
  console.log('[SQL Agent] Attempting to extract individual vulnerability objects...');

  const vulnerabilities = [];
  // Match objects that contain vulnerability_type field
  const objectPattern = /\{\s*"vulnerability_type"\s*:\s*"[^"]*"[^}]*\}/g;
  let match;

  while ((match = objectPattern.exec(cleaned)) !== null) {
    try {
      let objStr = match[0];
      const parsed = JSON.parse(objStr);
      if (isValidVulnerability(parsed)) {
        vulnerabilities.push(normalizeVulnerability(parsed));
        console.log(`[SQL Agent] Extracted vulnerability at line ${parsed.line_number}`);
      }
    } catch (e) {
      console.log('[SQL Agent] Failed to parse individual object, trying to fix...');
    }
  }

  console.log(`[SQL Agent] Regex extraction found: ${vulnerabilities.length} vulnerabilities`);

  // If we found fewer vulnerabilities than line numbers, use line number extraction
  if (vulnerabilities.length < foundLineNumbers.length) {
    console.log('[SQL Agent] Missing some vulnerabilities, using line number extraction...');

    // Get line numbers we already have
    const extractedLines = vulnerabilities.map((v) => v.line_number);
    console.log('[SQL Agent] Already extracted lines:', extractedLines);

    // Find missing line numbers
    const missingLines = foundLineNumbers.filter((ln) => !extractedLines.includes(ln));
    console.log('[SQL Agent] Missing lines:', missingLines);

    // Extract missing vulnerabilities using line numbers
    missingLines.forEach((lineNum) => {
      // Try to find the explanation for this line
      const explanationMatch = cleaned.match(
        new RegExp(`"line_number"\\s*:\\s*${lineNum}[^}]*"explanation"\\s*:\\s*"([^"]*)"`)
      );
      const explanation = explanationMatch
        ? explanationMatch[1]
        : 'SQL injection vulnerability detected';

      // Try to find code snippet - look between line_number and next key
      let snippet = '';
      const snippetRegex = new RegExp(
        `"line_number"\\s*:\\s*${lineNum}\\s*,\\s*"code_snippet"\\s*:\\s*"(.*?)"\\s*,\\s*"explanation"`,
        's'
      );
      const snippetMatch = cleaned.match(snippetRegex);
      if (snippetMatch) {
        snippet = snippetMatch[1];
      }

      vulnerabilities.push(
        normalizeVulnerability({
          vulnerability_type: 'SQL Injection',
          severity: 'CRITICAL',
          line_number: lineNum,
          code_snippet: snippet,
          explanation: explanation,
          fix_suggestion: 'Use parameterized queries instead of string concatenation',
          confidence: 0.9,
        })
      );

      console.log(`[SQL Agent] Added missing vulnerability at line ${lineNum}`);
    });

    // Sort by line number
    vulnerabilities.sort((a, b) => a.line_number - b.line_number);
  }

  console.log(`[SQL Agent] Final extraction: ${vulnerabilities.length} vulnerabilities`);
  return vulnerabilities;
}

/**
 * Parses the AI response - wrapper for backwards compatibility
 * @param {string} response - Raw AI response
 * @returns {Array} - Parsed vulnerability array
 */
function parseAIResponse(response) {
  return extractAndParseJSON(response);
}

/**
 * Checks if an object looks like a valid vulnerability
 * @param {object} obj - Object to validate
 * @returns {boolean} - True if valid
 */
function isValidVulnerability(obj) {
  if (!obj || typeof obj !== 'object') return false;
  // Must have at least vulnerability_type or line_number
  return obj.vulnerability_type || obj.line_number || obj.code_snippet;
}

/**
 * Normalizes a vulnerability object to the expected format
 * @param {object} vuln - Raw vulnerability object
 * @returns {object} - Normalized vulnerability
 */
function normalizeVulnerability(vuln) {
  return {
    vulnerability_type: String(vuln.vulnerability_type || 'SQL Injection'),
    severity: normalizeSeverity(vuln.severity),
    line_number: parseInt(vuln.line_number, 10) || 0,
    code_snippet: String(vuln.code_snippet || ''),
    explanation: String(vuln.explanation || ''),
    fix_suggestion: String(vuln.fix_suggestion || ''),
    confidence: normalizeConfidence(vuln.confidence),
  };
}

/**
 * Normalizes severity to expected values
 * @param {string} severity - Raw severity value
 * @returns {string} - Normalized severity
 */
function normalizeSeverity(severity) {
  const normalized = String(severity || '').toUpperCase().trim();
  const validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  return validSeverities.includes(normalized) ? normalized : 'HIGH';
}

/**
 * Normalizes confidence to a valid range
 * @param {number|string} confidence - Raw confidence value
 * @returns {number} - Normalized confidence between 0 and 1
 */
function normalizeConfidence(confidence) {
  const num = parseFloat(confidence);
  if (isNaN(num)) return 0.85;
  return Math.max(0, Math.min(1, num));
}

/**
 * Detects SQL injection vulnerabilities in code using Workers AI
 *
 * @param {string} code - The source code to analyze
 * @param {string} filename - Name of the file being analyzed
 * @param {string} language - Programming language (python, javascript, java, etc.)
 * @param {object} ai - Cloudflare AI binding from env.AI
 * @returns {Promise<Array>} - Array of vulnerability objects
 */
export async function detectSQLInjection(code, filename, language, ai) {
  console.log('[SQL Agent] ========================================');
  console.log('[SQL Agent] Starting SQL injection scan');
  console.log('[SQL Agent] Filename:', filename);
  console.log('[SQL Agent] Language:', language);
  console.log('[SQL Agent] Code length:', code?.length || 0, 'characters');
  console.log('[SQL Agent] AI binding exists:', !!ai);

  // Validate inputs
  if (!code || typeof code !== 'string' || code.trim().length === 0) {
    console.log('[SQL Agent] Skipping scan: empty code');
    return [];
  }

  if (!ai) {
    console.error('[SQL Agent] AI binding is not available!');
    throw new Error('AI binding not available. Make sure to run with --remote flag: npm run dev:remote');
  }

  try {
    // Log complete code with line numbers for verification
    const lines = code.split('\n');
    console.log('[SQL Agent] ========== CODE TO ANALYZE ==========');
    console.log(`[SQL Agent] Total lines: ${lines.length}`);
    lines.forEach((line, idx) => {
      // Highlight lines that likely contain SQL queries
      const hasSql = /SELECT|INSERT|UPDATE|DELETE|query\s*=|execute/i.test(line);
      const marker = hasSql ? ' <-- SQL' : '';
      console.log(`[SQL Agent]   ${idx + 1}: ${line}${marker}`);
    });
    console.log('[SQL Agent] ========== END CODE ==========');

    // Build the analysis prompt
    const prompt = buildPrompt(code, language);
    console.log('[SQL Agent] Prompt length:', prompt.length, 'characters');

    // Call Cloudflare Workers AI
    console.log('[SQL Agent] Calling Workers AI model:', MODEL);
    console.log('[SQL Agent] Requesting analysis of ALL', lines.length, 'lines...');
    const startTime = Date.now();

    const response = await ai.run(MODEL, {
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
      max_tokens: 8192, // Increased to ensure we get all vulnerabilities
      temperature: 0.1,
    });

    const elapsed = Date.now() - startTime;
    console.log('[SQL Agent] AI response received in', elapsed, 'ms');

    // Debug: Log the entire response structure
    console.log('[SQL Agent] Response type:', typeof response);
    console.log('[SQL Agent] Response keys:', response ? Object.keys(response) : 'null');

    // Extract the response text - try multiple possible paths
    let responseText = null;

    if (typeof response === 'string') {
      responseText = response;
    } else if (response) {
      // Try common response paths
      responseText =
        response.response ||
        response.result ||
        response.content ||
        response.text ||
        response.output ||
        response.generated_text ||
        (response.choices && response.choices[0]?.message?.content) ||
        (response.choices && response.choices[0]?.text);
    }

    console.log('[SQL Agent] Extracted response text type:', typeof responseText);
    console.log('[SQL Agent] Response text length:', responseText?.length || 0);

    if (!responseText) {
      console.error('[SQL Agent] Could not extract response text from AI response');
      console.error('[SQL Agent] Full response object:', JSON.stringify(response, null, 2).substring(0, 1000));
      return [];
    }

    // Parse and validate the response
    const vulnerabilities = parseAIResponse(responseText);

    // Calculate coverage statistics
    const totalLines = code.split('\n').length;
    const detectedLines = vulnerabilities.map((v) => v.line_number);
    const maxLineFound = detectedLines.length > 0 ? Math.max(...detectedLines) : 0;
    const minLineFound = detectedLines.length > 0 ? Math.min(...detectedLines) : 0;

    console.log('[SQL Agent] ========================================');
    console.log('[SQL Agent] SCAN RESULTS:');
    console.log(`[SQL Agent]   Total lines in file: ${totalLines}`);
    console.log(`[SQL Agent]   Vulnerabilities found: ${vulnerabilities.length}`);
    console.log(`[SQL Agent]   Line numbers detected: [${detectedLines.join(', ')}]`);
    console.log(`[SQL Agent]   Coverage: lines ${minLineFound} to ${maxLineFound} of ${totalLines}`);

    if (maxLineFound < totalLines * 0.5 && vulnerabilities.length > 0) {
      console.warn(`[SQL Agent] WARNING: Only scanned first half of file! May have missed vulnerabilities.`);
    }

    vulnerabilities.forEach((v, i) => {
      console.log(`[SQL Agent]   ${i + 1}. Line ${v.line_number}: ${v.severity} - ${v.code_snippet.substring(0, 60)}...`);
    });
    console.log('[SQL Agent] ========================================');

    // Validate line numbers are reasonable
    vulnerabilities.forEach((v) => {
      if (v.line_number < 1 || v.line_number > totalLines) {
        console.warn(`[SQL Agent] WARNING: Line ${v.line_number} is outside valid range (1-${totalLines})`);
      }
    });

    return vulnerabilities;
  } catch (error) {
    console.error('[SQL Agent] Error during scan:', error.message);
    console.error('[SQL Agent] Error stack:', error.stack);
    throw new Error(`SQL Injection scan failed: ${error.message}`);
  }
}
