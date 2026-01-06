/**
 * Static Analyzer
 *
 * Scans source code for common vulnerability patterns.
 * This is purely static analysis - no network activity, no execution.
 * It reads YOUR code and flags potential security issues.
 */

import { readdir, readFile, stat } from 'fs/promises';
import { join, extname } from 'path';

export class StaticAnalyzer {
  constructor(projectPath) {
    this.projectPath = projectPath;
    this.supportedExtensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.go'];
    this.findings = [];
  }

  /**
   * Vulnerability patterns to detect in source code
   * Each pattern includes:
   * - regex: Pattern to match
   * - severity: critical/high/medium/low/info
   * - title: Short description
   * - description: What the issue is
   * - remediation: How to fix it
   */
  static PATTERNS = {
    // SQL Injection risks (string concatenation in queries)
    sqlInjection: {
      patterns: [
        /(\$\{.*\}|\+\s*\w+\s*\+).*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)/gi,
        /query\s*\(\s*[`"'].*\$\{/gi,
        /execute\s*\(\s*f?[`"'].*\{/gi,
        /\.raw\s*\(\s*[`"'].*\$\{/gi,
      ],
      severity: 'critical',
      title: 'Potential SQL Injection',
      description: 'String interpolation in SQL queries can lead to SQL injection attacks.',
      remediation: 'Use parameterized queries or prepared statements. Example: db.query("SELECT * FROM users WHERE id = $1", [userId])'
    },

    // Hardcoded secrets
    hardcodedSecrets: {
      patterns: [
        /(?:api[_-]?key|apikey|secret|password|passwd|pwd|token|auth)[\s]*[:=][\s]*[`"'][^`"']{8,}[`"']/gi,
        /(?:aws|gcp|azure|stripe|twilio)[_-]?(?:key|secret|token)[\s]*[:=][\s]*[`"'][^`"']+[`"']/gi,
        /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
        /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, // JWT tokens
      ],
      severity: 'critical',
      title: 'Hardcoded Secret Detected',
      description: 'Secrets should never be hardcoded in source code.',
      remediation: 'Use environment variables or a secrets manager. Move secrets to .env files (which should be in .gitignore).'
    },

    // NoSQL Injection risks
    nosqlInjection: {
      patterns: [
        /\{\s*\$(?:where|gt|gte|lt|lte|ne|in|nin|regex)\s*:/gi,
        /find(?:One)?\s*\(\s*\{[^}]*\$(?:where|regex)/gi,
      ],
      severity: 'high',
      title: 'Potential NoSQL Injection',
      description: 'User input in MongoDB operators can lead to NoSQL injection.',
      remediation: 'Validate and sanitize user input. Use MongoDB sanitization libraries like mongo-sanitize.'
    },

    // XSS risks
    xssRisks: {
      patterns: [
        /innerHTML\s*=\s*(?!['"`]<)/g,
        /dangerouslySetInnerHTML/g,
        /document\.write\s*\(/g,
        /v-html\s*=/g,
        /\[innerHTML\]\s*=/g,
      ],
      severity: 'high',
      title: 'Potential Cross-Site Scripting (XSS)',
      description: 'Direct HTML injection can lead to XSS attacks.',
      remediation: 'Use textContent instead of innerHTML, or sanitize HTML with DOMPurify before rendering.'
    },

    // Insecure randomness
    insecureRandom: {
      patterns: [
        /Math\.random\s*\(\s*\)/g,
      ],
      severity: 'medium',
      title: 'Insecure Randomness',
      description: 'Math.random() is not cryptographically secure.',
      remediation: 'For security-sensitive operations, use crypto.randomBytes() or crypto.getRandomValues().'
    },

    // Eval and code execution
    codeExecution: {
      patterns: [
        /eval\s*\(/g,
        /new\s+Function\s*\(/g,
        /setTimeout\s*\(\s*[`"']/g,
        /setInterval\s*\(\s*[`"']/g,
        /exec\s*\(\s*[`"'].*\$\{/g,
        /child_process.*exec/g,
      ],
      severity: 'high',
      title: 'Potential Code Execution',
      description: 'Dynamic code execution can lead to remote code execution vulnerabilities.',
      remediation: 'Avoid eval() and dynamic code execution. Use safer alternatives like JSON.parse() for data parsing.'
    },

    // Path traversal
    pathTraversal: {
      patterns: [
        /(?:readFile|writeFile|createReadStream|createWriteStream)\s*\([^)]*(?:\+|`)/g,
        /path\.join\s*\([^)]*(?:req\.|request\.)/g,
      ],
      severity: 'high',
      title: 'Potential Path Traversal',
      description: 'Unsanitized file paths can allow attackers to access arbitrary files.',
      remediation: 'Validate and sanitize file paths. Use path.resolve() and verify the resolved path is within allowed directories.'
    },

    // Disabled security features
    disabledSecurity: {
      patterns: [
        /rejectUnauthorized\s*:\s*false/g,
        /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/g,
        /verify\s*=\s*False/g,
        /InsecureRequestWarning/g,
      ],
      severity: 'high',
      title: 'Disabled Security Feature',
      description: 'TLS/SSL verification has been disabled.',
      remediation: 'Enable TLS verification. Fix certificate issues instead of disabling verification.'
    },

    // Weak crypto
    weakCrypto: {
      patterns: [
        /createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/gi,
        /hashlib\.(?:md5|sha1)\s*\(/gi,
        /Digest::(?:MD5|SHA1)/g,
      ],
      severity: 'medium',
      title: 'Weak Cryptographic Algorithm',
      description: 'MD5 and SHA1 are considered weak for security purposes.',
      remediation: 'Use SHA-256 or stronger algorithms. For passwords, use bcrypt, scrypt, or Argon2.'
    },

    // CORS misconfiguration patterns
    corsMisconfig: {
      patterns: [
        /Access-Control-Allow-Origin['"]\s*:\s*['"]\*/g,
        /cors\s*\(\s*\{\s*origin\s*:\s*true/g,
        /cors\s*\(\s*\)/g,
      ],
      severity: 'medium',
      title: 'Permissive CORS Configuration',
      description: 'Overly permissive CORS can expose your API to unauthorized access.',
      remediation: 'Restrict CORS to specific trusted origins instead of using wildcard (*).'
    },
  };

  /**
   * Analyze all files in the project
   */
  async analyze() {
    this.findings = [];

    const files = await this.getSourceFiles(this.projectPath);

    for (const file of files) {
      await this.analyzeFile(file);
    }

    return {
      scannedFiles: files.length,
      findings: this.findings,
      summary: this.summarize()
    };
  }

  /**
   * Recursively get all source files
   */
  async getSourceFiles(dir, files = []) {
    const entries = await readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = join(dir, entry.name);

      // Skip common non-source directories
      if (entry.isDirectory()) {
        if (['node_modules', '.git', 'dist', 'build', '.next', '__pycache__', 'venv'].includes(entry.name)) {
          continue;
        }
        await this.getSourceFiles(fullPath, files);
      } else if (this.supportedExtensions.includes(extname(entry.name))) {
        files.push(fullPath);
      }
    }

    return files;
  }

  /**
   * Analyze a single file for vulnerabilities
   */
  async analyzeFile(filePath) {
    try {
      const content = await readFile(filePath, 'utf-8');
      const lines = content.split('\n');

      for (const [category, config] of Object.entries(StaticAnalyzer.PATTERNS)) {
        for (const pattern of config.patterns) {
          // Reset regex state
          pattern.lastIndex = 0;

          let match;
          while ((match = pattern.exec(content)) !== null) {
            // Find line number
            const lineNumber = this.getLineNumber(content, match.index);
            const lineContent = lines[lineNumber - 1]?.trim() || '';

            this.findings.push({
              category,
              severity: config.severity,
              title: config.title,
              description: config.description,
              remediation: config.remediation,
              location: {
                file: filePath.replace(this.projectPath, ''),
                line: lineNumber,
                snippet: lineContent.substring(0, 100) + (lineContent.length > 100 ? '...' : '')
              }
            });
          }
        }
      }
    } catch (err) {
      // Skip files that can't be read
      if (err.code !== 'ENOENT') {
        console.warn(`Warning: Could not analyze ${filePath}: ${err.message}`);
      }
    }
  }

  /**
   * Get line number from character index
   */
  getLineNumber(content, index) {
    return content.substring(0, index).split('\n').length;
  }

  /**
   * Generate summary statistics
   */
  summarize() {
    const summary = {
      total: this.findings.length,
      bySeverity: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      },
      byCategory: {}
    };

    for (const finding of this.findings) {
      summary.bySeverity[finding.severity]++;
      summary.byCategory[finding.category] = (summary.byCategory[finding.category] || 0) + 1;
    }

    return summary;
  }
}

export default StaticAnalyzer;
