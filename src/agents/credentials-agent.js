/**
 * Hard-coded Credentials Vulnerability Detection Agent
 *
 * Uses Cloudflare Workers AI (Llama 3.3) to analyze code
 * for hard-coded credentials and secrets.
 */

// The model to use for credentials detection
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
 * @param {string} code - Source code to analyze
 * @param {string} language - Programming language
 * @returns {string} - The formatted prompt
 */
function buildPrompt(code, language) {
  const numberedCode = addLineNumbers(code);
  const totalLines = code.split('\n').length;

  return `You are an expert security researcher specializing in detecting hard-coded credentials and secrets in source code.

CRITICAL REQUIREMENTS - READ CAREFULLY:
1. You MUST analyze the ENTIRE code file from line 1 to line ${totalLines}
2. You MUST find ALL hard-coded credentials, not just the first few
3. Do NOT stop scanning after finding 2-3 issues - continue to the END
4. EVERY variable assignment must be checked for credential patterns
5. Check EVERY line that contains credential-related variable names

TASK: Find ALL hard-coded credentials in this ${language} code (${totalLines} lines total).

CODE TO ANALYZE (line numbers shown before each line):
\`\`\`${language}
${numberedCode}
\`\`\`

CREDENTIAL PATTERNS TO DETECT - Check for ALL of these:

Pattern 1: API Keys
   VULNERABLE: API_KEY = "sk_live_abc123def456"
   VULNERABLE: api_key = "AIzaSyC-abc123def456"
   VULNERABLE: stripe_key = "pk_test_..."

Pattern 2: Passwords in code
   VULNERABLE: password = "MySecretPassword123"
   VULNERABLE: db_password = "admin123"
   VULNERABLE: user_pass = "password123"
   VULNERABLE: PASSWORD = "secret"

Pattern 3: Database connection strings with credentials
   VULNERABLE: connection_string = "mysql://user:password123@localhost/db"
   VULNERABLE: DATABASE_URL = "postgresql://admin:secret@host/db"

Pattern 4: AWS Credentials
   VULNERABLE: AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
   VULNERABLE: aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"

Pattern 5: Private Keys and Tokens
   VULNERABLE: private_key = "-----BEGIN RSA PRIVATE KEY-----..."
   VULNERABLE: auth_token = "eyJhbGciOiJIUzI1NiIs..."
   VULNERABLE: bearer_token = "ghp_abc123..."

Pattern 6: JWT Secrets
   VULNERABLE: JWT_SECRET = "my-super-secret-jwt-key"
   VULNERABLE: jwt_secret_key = "secretkey123"

Pattern 7: OAuth Secrets
   VULNERABLE: CLIENT_SECRET = "abc123-client-secret"
   VULNERABLE: oauth_secret = "secret_value"

Pattern 8: Generic Secrets
   VULNERABLE: SECRET_KEY = "django-insecure-abc123"
   VULNERABLE: encryption_key = "my-encryption-key"
   VULNERABLE: PRIVATE_KEY = "pk_..."

SAFE CODE (these are NOT vulnerabilities):
   SAFE: password = os.getenv('PASSWORD')
   SAFE: api_key = process.env.API_KEY
   SAFE: secret = os.environ.get('SECRET_KEY')
   SAFE: password = config.get('password')
   SAFE: token = await getSecret('auth_token')
   SAFE: API_KEY = None  # Placeholder
   SAFE: password = ""  # Empty string (but warn if used)
   SAFE: # password = "commented out"

VARIABLE NAME PATTERNS that indicate credentials:
- password, passwd, pwd, pass
- secret, secret_key, secretkey
- api_key, apikey, api_token
- token, auth_token, access_token, bearer_token
- private_key, privatekey
- credential, credentials, cred
- connection_string, conn_str
- aws_secret, aws_key
- jwt_secret, jwt_key
- client_secret, oauth_secret
- encryption_key, encrypt_key

ANALYSIS CHECKLIST - You must check ALL of these:
[ ] Line 1-10: Check for credentials
[ ] Line 11-20: Check for credentials
[ ] Line 21-30: Check for credentials
[ ] Line 31-${totalLines}: Check for credentials
[ ] All config objects checked
[ ] All variable assignments checked

For EACH hard-coded credential found, report:
- vulnerability_type: "Hard-coded Credentials"
- severity: "CRITICAL" (for production/live keys) or "HIGH" (for any hardcoded secret)
- line_number: The EXACT number shown at the start of the line (before the colon)
- code_snippet: The vulnerable code (without the line number prefix)
- explanation: What type of credential is exposed
- fix_suggestion: "Use environment variables instead" with specific example
- confidence: 0.95

RESPONSE FORMAT - Return ONLY a compact JSON array:
[{"vulnerability_type":"Hard-coded Credentials","severity":"CRITICAL","line_number":5,"code_snippet":"API_KEY = \\"sk_live_...\\","explanation":"Production API key hardcoded","fix_suggestion":"Use os.getenv('API_KEY') or process.env.API_KEY","confidence":0.95}]

CRITICAL FINAL REQUIREMENTS:
- Return ALL credentials found (if 6 exist, return all 6)
- Start response with [ and end with ]
- NO markdown, NO code blocks, NO explanations
- Keep explanations SHORT to fit all findings
- Use exact line numbers from the numbered code
- Mark live/production keys as CRITICAL, test/dev keys as HIGH

JSON ARRAY OUTPUT:`;
}

/**
 * Extracts and repairs JSON from AI response text
 * @param {string} text - Raw AI response text
 * @returns {Array} - Parsed vulnerability array
 */
function extractAndParseJSON(text) {
  if (!text) {
    console.log('[Credentials Agent] Empty response text');
    return [];
  }

  let cleaned = text.trim();

  console.log('[Credentials Agent] ===== COMPLETE AI RESPONSE =====');
  console.log(cleaned);
  console.log('[Credentials Agent] ===== END RESPONSE =====');
  console.log('[Credentials Agent] Response length:', cleaned.length, 'characters');

  // Remove markdown code blocks if present
  const codeBlockMatch = cleaned.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (codeBlockMatch) {
    console.log('[Credentials Agent] Extracted content from markdown code block');
    cleaned = codeBlockMatch[1].trim();
  }

  // Find where the JSON array starts
  const arrayStart = cleaned.indexOf('[');
  if (arrayStart === -1) {
    console.log('[Credentials Agent] No JSON array found in response');
    return [];
  }

  cleaned = cleaned.substring(arrayStart);

  // Try to parse as-is first
  try {
    const parsed = JSON.parse(cleaned);
    if (Array.isArray(parsed)) {
      console.log(`[Credentials Agent] Successfully parsed ${parsed.length} vulnerabilities directly`);
      return parsed.filter(isValidVulnerability).map(normalizeVulnerability);
    }
  } catch (e) {
    console.log('[Credentials Agent] Direct parse failed:', e.message);
  }

  // If truncated, try to repair
  if (!cleaned.trim().endsWith(']')) {
    console.log('[Credentials Agent] JSON array appears truncated, attempting repair...');
    const lastBrace = cleaned.lastIndexOf('}');
    if (lastBrace > 0) {
      const repaired = cleaned.substring(0, lastBrace + 1) + '\n]';
      try {
        const parsed = JSON.parse(repaired);
        if (Array.isArray(parsed)) {
          console.log(`[Credentials Agent] Repaired JSON: found ${parsed.length} vulnerabilities`);
          return parsed.filter(isValidVulnerability).map(normalizeVulnerability);
        }
      } catch (e) {
        console.log('[Credentials Agent] Repaired JSON parse failed:', e.message);
      }
    }
  }

  // Count line numbers mentioned in response
  const lineNumberPattern = /"line_number"\s*:\s*(\d+)/g;
  const foundLineNumbers = [];
  let lineMatch;

  while ((lineMatch = lineNumberPattern.exec(cleaned)) !== null) {
    const lineNum = parseInt(lineMatch[1], 10);
    if (!foundLineNumbers.includes(lineNum)) {
      foundLineNumbers.push(lineNum);
    }
  }

  console.log('[Credentials Agent] Line numbers found in response:', foundLineNumbers);

  // Try regex extraction for individual objects
  console.log('[Credentials Agent] Attempting to extract individual vulnerability objects...');

  const vulnerabilities = [];
  const objectPattern = /\{\s*"vulnerability_type"\s*:\s*"[^"]*"[^}]*\}/g;
  let match;

  while ((match = objectPattern.exec(cleaned)) !== null) {
    try {
      const parsed = JSON.parse(match[0]);
      if (isValidVulnerability(parsed)) {
        vulnerabilities.push(normalizeVulnerability(parsed));
        console.log(`[Credentials Agent] Extracted vulnerability at line ${parsed.line_number}`);
      }
    } catch (e) {
      console.log('[Credentials Agent] Failed to parse individual object');
    }
  }

  console.log(`[Credentials Agent] Regex extraction found: ${vulnerabilities.length} vulnerabilities`);

  // If we found fewer vulnerabilities than line numbers, extract missing ones
  if (vulnerabilities.length < foundLineNumbers.length) {
    console.log('[Credentials Agent] Missing some vulnerabilities, using line number extraction...');

    const extractedLines = vulnerabilities.map((v) => v.line_number);
    const missingLines = foundLineNumbers.filter((ln) => !extractedLines.includes(ln));

    missingLines.forEach((lineNum) => {
      const explanationMatch = cleaned.match(
        new RegExp(`"line_number"\\s*:\\s*${lineNum}[^}]*"explanation"\\s*:\\s*"([^"]*)"`)
      );
      const explanation = explanationMatch
        ? explanationMatch[1]
        : 'Hard-coded credential detected';

      vulnerabilities.push(
        normalizeVulnerability({
          vulnerability_type: 'Hard-coded Credentials',
          severity: 'HIGH',
          line_number: lineNum,
          code_snippet: '',
          explanation: explanation,
          fix_suggestion: 'Use environment variables instead',
          confidence: 0.9,
        })
      );

      console.log(`[Credentials Agent] Added missing vulnerability at line ${lineNum}`);
    });

    vulnerabilities.sort((a, b) => a.line_number - b.line_number);
  }

  console.log(`[Credentials Agent] Final extraction: ${vulnerabilities.length} vulnerabilities`);
  return vulnerabilities;
}

/**
 * Checks if an object looks like a valid vulnerability
 * @param {object} obj - Object to validate
 * @returns {boolean} - True if valid
 */
function isValidVulnerability(obj) {
  if (!obj || typeof obj !== 'object') return false;
  return obj.vulnerability_type || obj.line_number || obj.code_snippet;
}

/**
 * Normalizes a vulnerability object to the expected format
 * @param {object} vuln - Raw vulnerability object
 * @returns {object} - Normalized vulnerability
 */
function normalizeVulnerability(vuln) {
  return {
    vulnerability_type: String(vuln.vulnerability_type || 'Hard-coded Credentials'),
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
 * Detects hard-coded credentials in code using Workers AI
 *
 * @param {string} code - The source code to analyze
 * @param {string} filename - Name of the file being analyzed
 * @param {string} language - Programming language
 * @param {object} ai - Cloudflare AI binding from env.AI
 * @returns {Promise<Array>} - Array of vulnerability objects
 */
export async function detectHardcodedCredentials(code, filename, language, ai) {
  console.log('[Credentials Agent] ========================================');
  console.log('[Credentials Agent] Starting credentials scan');
  console.log('[Credentials Agent] Filename:', filename);
  console.log('[Credentials Agent] Language:', language);
  console.log('[Credentials Agent] Code length:', code?.length || 0, 'characters');
  console.log('[Credentials Agent] AI binding exists:', !!ai);

  if (!code || typeof code !== 'string' || code.trim().length === 0) {
    console.log('[Credentials Agent] Skipping scan: empty code');
    return [];
  }

  if (!ai) {
    console.error('[Credentials Agent] AI binding is not available!');
    throw new Error('AI binding not available. Make sure to run with --remote flag: npm run dev:remote');
  }

  try {
    const lines = code.split('\n');
    console.log('[Credentials Agent] ========== CODE TO ANALYZE ==========');
    console.log(`[Credentials Agent] Total lines: ${lines.length}`);
    lines.forEach((line, idx) => {
      const hasCredential = /password|secret|api[_-]?key|token|credential|private[_-]?key|aws|jwt/i.test(line);
      const marker = hasCredential ? ' <-- CRED' : '';
      console.log(`[Credentials Agent]   ${idx + 1}: ${line}${marker}`);
    });
    console.log('[Credentials Agent] ========== END CODE ==========');

    const prompt = buildPrompt(code, language);
    console.log('[Credentials Agent] Prompt length:', prompt.length, 'characters');

    console.log('[Credentials Agent] Calling Workers AI model:', MODEL);
    const startTime = Date.now();

    const response = await ai.run(MODEL, {
      messages: [
        {
          role: 'user',
          content: prompt,
        },
      ],
      max_tokens: 8192,
      temperature: 0.1,
    });

    const elapsed = Date.now() - startTime;
    console.log('[Credentials Agent] AI response received in', elapsed, 'ms');
    console.log('[Credentials Agent] Response type:', typeof response);
    console.log('[Credentials Agent] Response keys:', response ? Object.keys(response) : 'null');

    let responseText = null;

    if (typeof response === 'string') {
      responseText = response;
    } else if (response) {
      // Try common response paths - ensure we get a string
      const candidates = [
        response.response,
        response.result,
        response.content,
        response.text,
        response.output,
        response.generated_text,
        response.choices?.[0]?.message?.content,
        response.choices?.[0]?.text,
      ];

      for (const candidate of candidates) {
        if (typeof candidate === 'string') {
          responseText = candidate;
          break;
        } else if (candidate && typeof candidate === 'object') {
          // Handle nested response objects
          const nested = candidate.response || candidate.text || candidate.content;
          if (typeof nested === 'string') {
            responseText = nested;
            break;
          }
        }
      }

      // Last resort: check if response.response is an object with string content
      if (!responseText && response.response && typeof response.response === 'object') {
        console.log('[Credentials Agent] Response.response is an object, checking for nested text...');
        console.log('[Credentials Agent] response.response keys:', Object.keys(response.response));
        for (const key of Object.keys(response.response)) {
          if (typeof response.response[key] === 'string' && response.response[key].includes('[')) {
            responseText = response.response[key];
            break;
          }
        }
      }
    }

    console.log('[Credentials Agent] Extracted response text type:', typeof responseText);
    console.log('[Credentials Agent] Response text length:', responseText?.length || 0);

    if (!responseText) {
      console.error('[Credentials Agent] Could not extract response text from AI response');
      console.error('[Credentials Agent] Full response object:', JSON.stringify(response, null, 2).substring(0, 2000));

      // Try one more fallback - stringify and look for JSON array pattern
      const fullStr = JSON.stringify(response);
      const jsonMatch = fullStr.match(/\[.*"vulnerability_type".*\]/s);
      if (jsonMatch) {
        console.log('[Credentials Agent] Found JSON pattern in stringified response, attempting parse...');
        responseText = jsonMatch[0];
      } else {
        return [];
      }
    }

    const vulnerabilities = extractAndParseJSON(responseText);

    const totalLines = code.split('\n').length;
    const detectedLines = vulnerabilities.map((v) => v.line_number);

    console.log('[Credentials Agent] ========================================');
    console.log('[Credentials Agent] SCAN RESULTS:');
    console.log(`[Credentials Agent]   Total lines in file: ${totalLines}`);
    console.log(`[Credentials Agent]   Vulnerabilities found: ${vulnerabilities.length}`);
    console.log(`[Credentials Agent]   Line numbers detected: [${detectedLines.join(', ')}]`);
    vulnerabilities.forEach((v, i) => {
      console.log(`[Credentials Agent]   ${i + 1}. Line ${v.line_number}: ${v.severity} - ${v.code_snippet.substring(0, 60)}...`);
    });
    console.log('[Credentials Agent] ========================================');

    return vulnerabilities;
  } catch (error) {
    console.error('[Credentials Agent] Error during scan:', error.message);
    console.error('[Credentials Agent] Error stack:', error.stack);
    throw new Error(`Credentials scan failed: ${error.message}`);
  }
}
