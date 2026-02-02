/**
 * Cross-Site Scripting (XSS) Vulnerability Detection Agent
 *
 * Uses Cloudflare Workers AI (Llama 3.3) to analyze code
 * for XSS vulnerabilities.
 */

// The model to use for XSS detection
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

  return `You are an expert security researcher specializing in Cross-Site Scripting (XSS) vulnerabilities.

CRITICAL REQUIREMENTS - READ CAREFULLY:
1. You MUST analyze the ENTIRE code file from line 1 to line ${totalLines}
2. You MUST find ALL XSS vulnerabilities, not just the first few
3. Do NOT stop scanning after finding 2-3 vulnerabilities - continue to the END
4. EVERY function in the code must be analyzed completely
5. Check EVERY line that handles user input or renders HTML

TASK: Find ALL XSS vulnerabilities in this ${language} code (${totalLines} lines total).

CODE TO ANALYZE (line numbers shown before each line):
\`\`\`${language}
${numberedCode}
\`\`\`

XSS PATTERNS TO DETECT - Check for ALL of these:

Pattern 1: innerHTML with user input (JavaScript)
   VULNERABLE: element.innerHTML = userInput
   VULNERABLE: document.getElementById('x').innerHTML = data

Pattern 2: document.write() with user input
   VULNERABLE: document.write(userInput)
   VULNERABLE: document.write('<div>' + name + '</div>')

Pattern 3: eval() with user input
   VULNERABLE: eval(userInput)
   VULNERABLE: new Function(userInput)()

Pattern 4: dangerouslySetInnerHTML in React
   VULNERABLE: <div dangerouslySetInnerHTML={{__html: userInput}} />

Pattern 5: jQuery .html() with user input
   VULNERABLE: $(element).html(userInput)
   VULNERABLE: $('#div').html(data)

Pattern 6: outerHTML with user input
   VULNERABLE: element.outerHTML = userInput

Pattern 7: insertAdjacentHTML with user input
   VULNERABLE: element.insertAdjacentHTML('beforeend', userInput)

Pattern 8: Unescaped template rendering (Python Flask/Django)
   VULNERABLE: render_template_string(user_input)
   VULNERABLE: {{ user_input | safe }}
   VULNERABLE: mark_safe(user_input)

Pattern 9: Direct HTML string concatenation
   VULNERABLE: html = '<div>' + user_input + '</div>'
   VULNERABLE: response = f"<html>{user_data}</html>"

SAFE CODE (these are NOT vulnerabilities):
   SAFE: element.textContent = userInput
   SAFE: element.innerText = userInput
   SAFE: DOMPurify.sanitize(userInput)
   SAFE: escape(userInput) before rendering
   SAFE: {{ user_input }} (auto-escaped in most template engines)

ANALYSIS CHECKLIST - You must check ALL of these:
[ ] Line 1-10: Check for vulnerabilities
[ ] Line 11-20: Check for vulnerabilities
[ ] Line 21-30: Check for vulnerabilities
[ ] Line 31-${totalLines}: Check for vulnerabilities
[ ] All functions analyzed

For EACH vulnerability found, report:
- vulnerability_type: "Cross-Site Scripting (XSS)"
- severity: "HIGH" or "CRITICAL" (for direct user input in HTML)
- line_number: The EXACT number shown at the start of the line (before the colon)
- code_snippet: The vulnerable code (without the line number prefix)
- explanation: Why this is vulnerable
- fix_suggestion: How to fix (use textContent, DOMPurify, escaping, etc.)
- confidence: 0.95

RESPONSE FORMAT - Return ONLY a compact JSON array:
[{"vulnerability_type":"Cross-Site Scripting (XSS)","severity":"HIGH","line_number":5,"code_snippet":"element.innerHTML = userInput","explanation":"User input directly inserted into innerHTML","fix_suggestion":"Use textContent or DOMPurify.sanitize()","confidence":0.95}]

CRITICAL FINAL REQUIREMENTS:
- Return ALL vulnerabilities (if 5 exist, return all 5)
- Start response with [ and end with ]
- NO markdown, NO code blocks, NO explanations
- Keep explanations SHORT to fit all vulnerabilities
- Use exact line numbers from the numbered code

JSON ARRAY OUTPUT:`;
}

/**
 * Extracts and repairs JSON from AI response text
 * @param {string} text - Raw AI response text
 * @returns {Array} - Parsed vulnerability array
 */
function extractAndParseJSON(text) {
  if (!text) {
    console.log('[XSS Agent] Empty response text');
    return [];
  }

  let cleaned = text.trim();

  console.log('[XSS Agent] ===== COMPLETE AI RESPONSE =====');
  console.log(cleaned);
  console.log('[XSS Agent] ===== END RESPONSE =====');
  console.log('[XSS Agent] Response length:', cleaned.length, 'characters');

  // Remove markdown code blocks if present
  const codeBlockMatch = cleaned.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (codeBlockMatch) {
    console.log('[XSS Agent] Extracted content from markdown code block');
    cleaned = codeBlockMatch[1].trim();
  }

  // Find where the JSON array starts
  const arrayStart = cleaned.indexOf('[');
  if (arrayStart === -1) {
    console.log('[XSS Agent] No JSON array found in response');
    return [];
  }

  cleaned = cleaned.substring(arrayStart);

  // Try to parse as-is first
  try {
    const parsed = JSON.parse(cleaned);
    if (Array.isArray(parsed)) {
      console.log(`[XSS Agent] Successfully parsed ${parsed.length} vulnerabilities directly`);
      return parsed.filter(isValidVulnerability).map(normalizeVulnerability);
    }
  } catch (e) {
    console.log('[XSS Agent] Direct parse failed:', e.message);
  }

  // If truncated, try to repair
  if (!cleaned.trim().endsWith(']')) {
    console.log('[XSS Agent] JSON array appears truncated, attempting repair...');
    const lastBrace = cleaned.lastIndexOf('}');
    if (lastBrace > 0) {
      const repaired = cleaned.substring(0, lastBrace + 1) + '\n]';
      try {
        const parsed = JSON.parse(repaired);
        if (Array.isArray(parsed)) {
          console.log(`[XSS Agent] Repaired JSON: found ${parsed.length} vulnerabilities`);
          return parsed.filter(isValidVulnerability).map(normalizeVulnerability);
        }
      } catch (e) {
        console.log('[XSS Agent] Repaired JSON parse failed:', e.message);
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

  console.log('[XSS Agent] Line numbers found in response:', foundLineNumbers);

  // Try regex extraction for individual objects
  console.log('[XSS Agent] Attempting to extract individual vulnerability objects...');

  const vulnerabilities = [];
  const objectPattern = /\{\s*"vulnerability_type"\s*:\s*"[^"]*"[^}]*\}/g;
  let match;

  while ((match = objectPattern.exec(cleaned)) !== null) {
    try {
      const parsed = JSON.parse(match[0]);
      if (isValidVulnerability(parsed)) {
        vulnerabilities.push(normalizeVulnerability(parsed));
        console.log(`[XSS Agent] Extracted vulnerability at line ${parsed.line_number}`);
      }
    } catch (e) {
      console.log('[XSS Agent] Failed to parse individual object');
    }
  }

  console.log(`[XSS Agent] Regex extraction found: ${vulnerabilities.length} vulnerabilities`);

  // If we found fewer vulnerabilities than line numbers, extract missing ones
  if (vulnerabilities.length < foundLineNumbers.length) {
    console.log('[XSS Agent] Missing some vulnerabilities, using line number extraction...');

    const extractedLines = vulnerabilities.map((v) => v.line_number);
    const missingLines = foundLineNumbers.filter((ln) => !extractedLines.includes(ln));

    missingLines.forEach((lineNum) => {
      const explanationMatch = cleaned.match(
        new RegExp(`"line_number"\\s*:\\s*${lineNum}[^}]*"explanation"\\s*:\\s*"([^"]*)"`)
      );
      const explanation = explanationMatch
        ? explanationMatch[1]
        : 'XSS vulnerability detected';

      vulnerabilities.push(
        normalizeVulnerability({
          vulnerability_type: 'Cross-Site Scripting (XSS)',
          severity: 'HIGH',
          line_number: lineNum,
          code_snippet: '',
          explanation: explanation,
          fix_suggestion: 'Use textContent, DOMPurify, or proper escaping',
          confidence: 0.9,
        })
      );

      console.log(`[XSS Agent] Added missing vulnerability at line ${lineNum}`);
    });

    vulnerabilities.sort((a, b) => a.line_number - b.line_number);
  }

  console.log(`[XSS Agent] Final extraction: ${vulnerabilities.length} vulnerabilities`);
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
    vulnerability_type: String(vuln.vulnerability_type || 'Cross-Site Scripting (XSS)'),
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
 * Detects XSS vulnerabilities in code using Workers AI
 *
 * @param {string} code - The source code to analyze
 * @param {string} filename - Name of the file being analyzed
 * @param {string} language - Programming language
 * @param {object} ai - Cloudflare AI binding from env.AI
 * @returns {Promise<Array>} - Array of vulnerability objects
 */
export async function detectXSS(code, filename, language, ai) {
  console.log('[XSS Agent] ========================================');
  console.log('[XSS Agent] Starting XSS scan');
  console.log('[XSS Agent] Filename:', filename);
  console.log('[XSS Agent] Language:', language);
  console.log('[XSS Agent] Code length:', code?.length || 0, 'characters');
  console.log('[XSS Agent] AI binding exists:', !!ai);

  if (!code || typeof code !== 'string' || code.trim().length === 0) {
    console.log('[XSS Agent] Skipping scan: empty code');
    return [];
  }

  if (!ai) {
    console.error('[XSS Agent] AI binding is not available!');
    throw new Error('AI binding not available. Make sure to run with --remote flag: npm run dev:remote');
  }

  try {
    const lines = code.split('\n');
    console.log('[XSS Agent] ========== CODE TO ANALYZE ==========');
    console.log(`[XSS Agent] Total lines: ${lines.length}`);
    lines.forEach((line, idx) => {
      const hasXss = /innerHTML|outerHTML|document\.write|eval\(|\.html\(|dangerouslySetInnerHTML|insertAdjacentHTML|mark_safe|render_template_string/i.test(line);
      const marker = hasXss ? ' <-- XSS' : '';
      console.log(`[XSS Agent]   ${idx + 1}: ${line}${marker}`);
    });
    console.log('[XSS Agent] ========== END CODE ==========');

    const prompt = buildPrompt(code, language);
    console.log('[XSS Agent] Prompt length:', prompt.length, 'characters');

    console.log('[XSS Agent] Calling Workers AI model:', MODEL);
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
    console.log('[XSS Agent] AI response received in', elapsed, 'ms');
    console.log('[XSS Agent] Response type:', typeof response);
    console.log('[XSS Agent] Response keys:', response ? Object.keys(response) : 'null');

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
        console.log('[XSS Agent] Response.response is an object, checking for nested text...');
        console.log('[XSS Agent] response.response keys:', Object.keys(response.response));
        for (const key of Object.keys(response.response)) {
          if (typeof response.response[key] === 'string' && response.response[key].includes('[')) {
            responseText = response.response[key];
            break;
          }
        }
      }
    }

    console.log('[XSS Agent] Extracted response text type:', typeof responseText);
    console.log('[XSS Agent] Response text length:', responseText?.length || 0);

    if (!responseText) {
      console.error('[XSS Agent] Could not extract response text from AI response');
      console.error('[XSS Agent] Full response object:', JSON.stringify(response, null, 2).substring(0, 2000));

      // Try one more fallback - stringify and look for JSON array pattern
      const fullStr = JSON.stringify(response);
      const jsonMatch = fullStr.match(/\[.*"vulnerability_type".*\]/s);
      if (jsonMatch) {
        console.log('[XSS Agent] Found JSON pattern in stringified response, attempting parse...');
        responseText = jsonMatch[0];
      } else {
        return [];
      }
    }

    const vulnerabilities = extractAndParseJSON(responseText);

    const totalLines = code.split('\n').length;
    const detectedLines = vulnerabilities.map((v) => v.line_number);

    console.log('[XSS Agent] ========================================');
    console.log('[XSS Agent] SCAN RESULTS:');
    console.log(`[XSS Agent]   Total lines in file: ${totalLines}`);
    console.log(`[XSS Agent]   Vulnerabilities found: ${vulnerabilities.length}`);
    console.log(`[XSS Agent]   Line numbers detected: [${detectedLines.join(', ')}]`);
    vulnerabilities.forEach((v, i) => {
      console.log(`[XSS Agent]   ${i + 1}. Line ${v.line_number}: ${v.severity} - ${v.code_snippet.substring(0, 60)}...`);
    });
    console.log('[XSS Agent] ========================================');

    return vulnerabilities;
  } catch (error) {
    console.error('[XSS Agent] Error during scan:', error.message);
    console.error('[XSS Agent] Error stack:', error.stack);
    throw new Error(`XSS scan failed: ${error.message}`);
  }
}
