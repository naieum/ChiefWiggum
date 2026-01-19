/**
 * Security Pattern Utilities
 *
 * Shared patterns and utilities for security scanning.
 */

/**
 * Database-specific security checks
 */
export const DatabaseChecks = {
  /**
   * Postgres/Supabase specific patterns
   */
  postgres: {
    // Patterns that indicate parameterized queries (GOOD)
    safePatterns: [
      /\$\d+/g,  // $1, $2 placeholders
      /\?\s*,/g, // ? placeholders
      /:\w+/g,   // :named placeholders
    ],

    // Check if a query uses safe parameterization
    isSafeQuery(query) {
      return this.safePatterns.some(p => p.test(query));
    },

    // RLS policy validation helpers
    rlsPatterns: {
      enableRls: /ALTER\s+TABLE\s+(\w+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi,
      createPolicy: /CREATE\s+POLICY\s+(\w+)\s+ON\s+(\w+)/gi,
      forceRls: /ALTER\s+TABLE\s+(\w+)\s+FORCE\s+ROW\s+LEVEL\s+SECURITY/gi,
    }
  },

  /**
   * MongoDB specific patterns
   */
  mongodb: {
    // Dangerous operators that shouldn't come from user input
    dangerousOperators: ['$where', '$regex', '$gt', '$gte', '$lt', '$lte', '$ne', '$in', '$nin'],

    // Check if an object contains dangerous operators
    hasDangerousOperator(obj) {
      if (typeof obj !== 'object' || obj === null) return false;

      for (const key of Object.keys(obj)) {
        if (this.dangerousOperators.includes(key)) return true;
        if (typeof obj[key] === 'object' && this.hasDangerousOperator(obj[key])) return true;
      }
      return false;
    }
  }
};

/**
 * Common vulnerability patterns by language
 */
export const LanguagePatterns = {
  javascript: {
    injection: [
      { pattern: /eval\s*\(/, name: 'eval()' },
      { pattern: /new\s+Function\s*\(/, name: 'new Function()' },
      { pattern: /innerHTML\s*=/, name: 'innerHTML assignment' },
      { pattern: /document\.write\s*\(/, name: 'document.write()' },
    ],
    secrets: [
      { pattern: /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/i, name: 'API Key' },
      { pattern: /password\s*[:=]\s*['"][^'"]+['"]/i, name: 'Password' },
    ]
  },

  python: {
    injection: [
      { pattern: /eval\s*\(/, name: 'eval()' },
      { pattern: /exec\s*\(/, name: 'exec()' },
      { pattern: /subprocess.*shell\s*=\s*True/, name: 'shell=True' },
      { pattern: /os\.system\s*\(/, name: 'os.system()' },
    ],
    secrets: [
      { pattern: /api[_-]?key\s*=\s*['"][^'"]+['"]/i, name: 'API Key' },
      { pattern: /password\s*=\s*['"][^'"]+['"]/i, name: 'Password' },
    ]
  }
};

/**
 * Severity scoring helpers
 */
export const Severity = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',

  /**
   * Get numeric score for severity
   */
  toScore(severity) {
    const scores = { critical: 10, high: 7, medium: 4, low: 2, info: 0 };
    return scores[severity] || 0;
  },

  /**
   * Compare severities
   */
  compare(a, b) {
    return this.toScore(b) - this.toScore(a);
  }
};

export default { DatabaseChecks, LanguagePatterns, Severity };
