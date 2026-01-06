/**
 * JSON Reporter
 *
 * Generates structured security reports in JSON format.
 * Follows a consistent schema with severity, impact, and remediation.
 */

export class Reporter {
  constructor(options = {}) {
    this.options = {
      includeMetadata: true,
      ...options
    };
  }

  /**
   * JSON Schema for security findings
   * This schema can be used for validation and documentation
   */
  static SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Guardian-Agent Security Report",
    "type": "object",
    "required": ["metadata", "summary", "findings"],
    "properties": {
      "metadata": {
        "type": "object",
        "properties": {
          "generatedAt": { "type": "string", "format": "date-time" },
          "generatorVersion": { "type": "string" },
          "projectPath": { "type": "string" }
        }
      },
      "summary": {
        "type": "object",
        "properties": {
          "totalFindings": { "type": "integer" },
          "bySeverity": {
            "type": "object",
            "properties": {
              "critical": { "type": "integer" },
              "high": { "type": "integer" },
              "medium": { "type": "integer" },
              "low": { "type": "integer" },
              "info": { "type": "integer" }
            }
          },
          "riskScore": {
            "type": "integer",
            "minimum": 0,
            "maximum": 100
          }
        }
      },
      "findings": {
        "type": "array",
        "items": {
          "type": "object",
          "required": ["id", "severity", "title", "description", "remediation"],
          "properties": {
            "id": { "type": "string" },
            "category": {
              "type": "string",
              "enum": ["static-analysis", "configuration", "safe-check"]
            },
            "severity": {
              "type": "string",
              "enum": ["critical", "high", "medium", "low", "info"]
            },
            "title": { "type": "string" },
            "description": { "type": "string" },
            "impact": { "type": "string" },
            "remediation": { "type": "string" },
            "location": {
              "type": "object",
              "properties": {
                "file": { "type": "string" },
                "line": { "type": "integer" },
                "endpoint": { "type": "string" },
                "snippet": { "type": "string" }
              }
            },
            "references": {
              "type": "array",
              "items": { "type": "string" }
            }
          }
        }
      }
    }
  };

  /**
   * Impact descriptions by vulnerability type
   */
  static IMPACT_MAP = {
    sqlInjection: 'Attackers could read, modify, or delete database data. In severe cases, command execution on the database server.',
    nosqlInjection: 'Attackers could bypass authentication, access unauthorized data, or perform denial of service.',
    xssRisks: 'Attackers could steal session cookies, redirect users, or perform actions on behalf of victims.',
    hardcodedSecrets: 'Exposed credentials could allow unauthorized access to external services or databases.',
    codeExecution: 'Attackers could execute arbitrary code on the server, leading to full system compromise.',
    pathTraversal: 'Attackers could read sensitive files outside the intended directory.',
    weakCrypto: 'Weak hashing allows attackers to reverse hashes and discover original values.',
    disabledSecurity: 'Disabled TLS verification allows man-in-the-middle attacks.',
    corsMisconfig: 'Overly permissive CORS could allow unauthorized cross-origin requests.',
    insecureRandom: 'Predictable values could allow attackers to guess tokens or session IDs.',
    configuration: 'Misconfiguration could expose sensitive data or allow unauthorized access.'
  };

  /**
   * Reference links for common vulnerabilities
   */
  static REFERENCES = {
    sqlInjection: [
      'https://owasp.org/www-community/attacks/SQL_Injection',
      'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
    ],
    nosqlInjection: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection'
    ],
    xssRisks: [
      'https://owasp.org/www-community/attacks/xss/',
      'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
    ],
    hardcodedSecrets: [
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'
    ],
    codeExecution: [
      'https://owasp.org/www-community/attacks/Code_Injection'
    ],
    pathTraversal: [
      'https://owasp.org/www-community/attacks/Path_Traversal'
    ]
  };

  /**
   * Generate a full report from findings
   */
  generate(findings) {
    const enrichedFindings = findings.map((finding, index) => this.enrichFinding(finding, index));

    const report = {
      metadata: this.generateMetadata(),
      summary: this.generateSummary(enrichedFindings),
      findings: enrichedFindings
    };

    return report;
  }

  /**
   * Enrich a finding with additional context
   */
  enrichFinding(finding, index) {
    const category = finding.category || 'unknown';

    return {
      id: `GUARD-${String(index + 1).padStart(4, '0')}`,
      category,
      severity: finding.severity,
      title: finding.title,
      description: finding.description,
      impact: finding.impact || Reporter.IMPACT_MAP[finding.category] || Reporter.IMPACT_MAP.configuration,
      remediation: finding.remediation,
      location: finding.location || {},
      references: Reporter.REFERENCES[finding.category] || []
    };
  }

  /**
   * Generate report metadata
   */
  generateMetadata() {
    return {
      generatedAt: new Date().toISOString(),
      generatorVersion: '1.0.0',
      tool: 'Guardian-Agent',
      disclaimer: 'This report is for self-assessment of your own projects only.'
    };
  }

  /**
   * Generate summary statistics
   */
  generateSummary(findings) {
    const bySeverity = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };

    const byCategory = {};

    for (const finding of findings) {
      bySeverity[finding.severity]++;
      byCategory[finding.category] = (byCategory[finding.category] || 0) + 1;
    }

    // Calculate risk score (0-100)
    const riskScore = Math.min(100,
      bySeverity.critical * 25 +
      bySeverity.high * 10 +
      bySeverity.medium * 3 +
      bySeverity.low * 1
    );

    return {
      totalFindings: findings.length,
      bySeverity,
      byCategory,
      riskScore,
      riskLevel: this.getRiskLevel(riskScore)
    };
  }

  /**
   * Get human-readable risk level
   */
  getRiskLevel(score) {
    if (score >= 75) return 'CRITICAL';
    if (score >= 50) return 'HIGH';
    if (score >= 25) return 'MEDIUM';
    if (score >= 10) return 'LOW';
    return 'MINIMAL';
  }

  /**
   * Export report to different formats
   */
  toJSON(report) {
    return JSON.stringify(report, null, 2);
  }

  toMarkdown(report) {
    let md = `# Guardian-Agent Security Report\n\n`;
    md += `**Generated:** ${report.metadata.generatedAt}\n`;
    md += `**Risk Level:** ${report.summary.riskLevel} (Score: ${report.summary.riskScore}/100)\n\n`;

    md += `## Summary\n\n`;
    md += `| Severity | Count |\n|----------|-------|\n`;
    for (const [sev, count] of Object.entries(report.summary.bySeverity)) {
      md += `| ${sev.toUpperCase()} | ${count} |\n`;
    }

    md += `\n## Findings\n\n`;

    for (const finding of report.findings) {
      md += `### ${finding.id}: ${finding.title}\n\n`;
      md += `**Severity:** ${finding.severity.toUpperCase()}\n\n`;
      md += `**Description:** ${finding.description}\n\n`;
      if (finding.location.file) {
        md += `**Location:** ${finding.location.file}`;
        if (finding.location.line) md += `:${finding.location.line}`;
        md += `\n\n`;
      }
      md += `**Impact:** ${finding.impact}\n\n`;
      md += `**Remediation:** ${finding.remediation}\n\n`;
      md += `---\n\n`;
    }

    return md;
  }
}

export default Reporter;
