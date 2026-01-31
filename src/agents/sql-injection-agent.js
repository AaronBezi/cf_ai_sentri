/**
 * SQL Injection Vulnerability Detection Agent
 *
 * Uses Cloudflare Workers AI (Llama 3.3) to analyze code
 * for SQL injection vulnerabilities.
 */

// The model to use for SQL injection detection
const MODEL = '@cf/meta/llama-3.3-70b-instruct-fp8-fast';

/**
 * Constructs the prompt for the AI model
 * @param {string} code - Source code to analyze
 * @param {string} language - Programming language
 * @returns {string} - The formatted prompt
 */
function buildPrompt(code, language) {
  return `You are an expert security analyst specializing in SQL injection vulnerability detection.

Analyze the following ${language} code for SQL injection vulnerabilities. Look for:
- String concatenation used to build SQL queries
- User input directly inserted into SQL strings
- f-strings or template literals in SQL queries
- Missing use of parameterized queries or prepared statements
- Dynamic SQL construction without proper sanitization

Code to analyze:

\`\`\`${language}
${code}
\`\`\`

For each vulnerability found, identify:
1. The exact line number where the vulnerability occurs
2. The vulnerable code snippet
3. Why it's vulnerable (detailed explanation)
4. How to fix it with a specific code example
5. Severity rating: CRITICAL (exploitable with no auth), HIGH (exploitable with some conditions), MEDIUM (requires specific circumstances), LOW (theoretical risk)
6. Confidence score from 0.0 to 1.0

Return ONLY a valid JSON array with this exact format (no other text, no markdown, no explanation):
[
  {
    "vulnerability_type": "SQL Injection",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "line_number": <number>,
    "code_snippet": "<the vulnerable line of code>",
    "explanation": "<detailed explanation of why this is vulnerable>",
    "fix_suggestion": "<specific code example showing the fix>",
    "confidence": <0.0-1.0>
  }
]

If no SQL injection vulnerabilities are found, return an empty array: []

Important: Return ONLY the JSON array, no other text before or after.`;
}

/**
 * Parses the AI response, handling potential markdown formatting
 * @param {string} response - Raw AI response
 * @returns {Array} - Parsed vulnerability array
 */
function parseAIResponse(response) {
  if (!response || typeof response !== 'string') {
    return [];
  }

  let jsonString = response.trim();

  // Remove markdown code block formatting if present
  // Handle ```json ... ``` or ``` ... ```
  const jsonBlockMatch = jsonString.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (jsonBlockMatch) {
    jsonString = jsonBlockMatch[1].trim();
  }

  // Try to find JSON array in the response
  const arrayMatch = jsonString.match(/\[[\s\S]*\]/);
  if (arrayMatch) {
    jsonString = arrayMatch[0];
  }

  try {
    const parsed = JSON.parse(jsonString);

    // Ensure it's an array
    if (!Array.isArray(parsed)) {
      console.warn('AI response is not an array, wrapping it');
      return [parsed];
    }

    // Validate and normalize each vulnerability object
    return parsed.map((vuln) => ({
      vulnerability_type: vuln.vulnerability_type || 'SQL Injection',
      severity: normalizeSeverity(vuln.severity),
      line_number: parseInt(vuln.line_number, 10) || 0,
      code_snippet: String(vuln.code_snippet || ''),
      explanation: String(vuln.explanation || ''),
      fix_suggestion: String(vuln.fix_suggestion || ''),
      confidence: normalizeConfidence(vuln.confidence),
    }));
  } catch (parseError) {
    console.error('Failed to parse AI response:', parseError.message);
    console.error('Raw response:', jsonString.substring(0, 500));
    return [];
  }
}

/**
 * Normalizes severity to expected values
 * @param {string} severity - Raw severity value
 * @returns {string} - Normalized severity
 */
function normalizeSeverity(severity) {
  const normalized = String(severity).toUpperCase().trim();
  const validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  return validSeverities.includes(normalized) ? normalized : 'MEDIUM';
}

/**
 * Normalizes confidence to a valid range
 * @param {number|string} confidence - Raw confidence value
 * @returns {number} - Normalized confidence between 0 and 1
 */
function normalizeConfidence(confidence) {
  const num = parseFloat(confidence);
  if (isNaN(num)) return 0.5;
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
  // Validate inputs
  if (!code || typeof code !== 'string' || code.trim().length === 0) {
    console.log(`Skipping SQL injection scan for ${filename}: empty code`);
    return [];
  }

  if (!ai) {
    throw new Error('AI binding not available. Ensure env.AI is configured in wrangler.toml');
  }

  try {
    console.log(`Scanning ${filename} (${language}) for SQL injection vulnerabilities...`);

    // Build the analysis prompt
    const prompt = buildPrompt(code, language);

    // Call Cloudflare Workers AI
    const response = await ai.run(MODEL, {
      messages: [
        {
          role: 'system',
          content:
            'You are a security expert. Analyze code for SQL injection vulnerabilities and return results as a JSON array only.',
        },
        {
          role: 'user',
          content: prompt,
        },
      ],
      max_tokens: 2048,
      temperature: 0.1, // Low temperature for more consistent, focused responses
    });

    // Extract the response text
    const responseText = response?.response || response?.result || '';

    if (!responseText) {
      console.warn(`Empty response from AI for ${filename}`);
      return [];
    }

    // Parse and validate the response
    const vulnerabilities = parseAIResponse(responseText);

    console.log(
      `Found ${vulnerabilities.length} SQL injection vulnerabilities in ${filename}`
    );

    return vulnerabilities;
  } catch (error) {
    console.error(`SQL Injection detection failed for ${filename}:`, error.message);

    // Re-throw with more context
    throw new Error(`SQL Injection scan failed: ${error.message}`);
  }
}
