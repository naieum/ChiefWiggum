/**
 * Security Score Calculator
 *
 * Provides an A-F grade for project security posture.
 * Makes security status immediately understandable.
 */

import { readFile } from 'fs/promises';
import { join } from 'path';

export class SecurityScoreCalculator {
  constructor(projectPath) {
    this.projectPath = projectPath;
  }

  /**
   * Calculate security score from findings
   * Returns A-F grade with breakdown
   */
  calculate(findings) {
    // Weight by severity
    const weights = {
      critical: 25,
      high: 10,
      medium: 3,
      low: 1,
      info: 0
    };

    // Count by severity
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const finding of findings) {
      counts[finding.severity]++;
    }

    // Calculate deductions
    let deductions = 0;
    for (const [severity, count] of Object.entries(counts)) {
      deductions += count * weights[severity];
    }

    // Start with 100, subtract deductions
    let score = Math.max(0, 100 - deductions);

    // Determine grade
    const grade = this.getGrade(score);

    // Generate breakdown
    const breakdown = this.generateBreakdown(counts, findings);

    // Top issues to fix
    const topIssues = this.getTopIssues(findings);

    return {
      score,
      grade: grade.letter,
      gradeColor: grade.color,
      gradeEmoji: grade.emoji,
      breakdown,
      topIssues,
      summary: this.generateSummary(grade, counts),
      recommendations: this.getRecommendations(grade, counts, findings)
    };
  }

  /**
   * Get letter grade from score
   */
  getGrade(score) {
    if (score >= 90) return { letter: 'A', color: 'green', emoji: '🛡️', description: 'Excellent' };
    if (score >= 80) return { letter: 'B', color: 'lightgreen', emoji: '✅', description: 'Good' };
    if (score >= 70) return { letter: 'C', color: 'yellow', emoji: '⚠️', description: 'Fair' };
    if (score >= 60) return { letter: 'D', color: 'orange', emoji: '🔶', description: 'Poor' };
    return { letter: 'F', color: 'red', emoji: '🚨', description: 'Critical' };
  }

  /**
   * Generate severity breakdown
   */
  generateBreakdown(counts, findings) {
    const categories = {};

    for (const finding of findings) {
      const cat = finding.category || 'other';
      if (!categories[cat]) {
        categories[cat] = { count: 0, severities: {} };
      }
      categories[cat].count++;
      categories[cat].severities[finding.severity] =
        (categories[cat].severities[finding.severity] || 0) + 1;
    }

    return {
      bySeverity: counts,
      byCategory: categories,
      total: findings.length
    };
  }

  /**
   * Get top issues to fix (prioritized)
   */
  getTopIssues(findings, limit = 5) {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

    const sorted = [...findings].sort((a, b) => {
      return severityOrder[a.severity] - severityOrder[b.severity];
    });

    return sorted.slice(0, limit).map(f => ({
      severity: f.severity,
      title: f.title,
      location: f.location?.file || 'Project-wide',
      quickFix: f.remediation?.split('\n')[0] || 'See finding details'
    }));
  }

  /**
   * Generate human-readable summary
   */
  generateSummary(grade, counts) {
    const parts = [];

    if (counts.critical > 0) {
      parts.push(`${counts.critical} critical issue${counts.critical > 1 ? 's' : ''} requiring immediate attention`);
    }
    if (counts.high > 0) {
      parts.push(`${counts.high} high severity issue${counts.high > 1 ? 's' : ''}`);
    }
    if (counts.medium > 0) {
      parts.push(`${counts.medium} medium severity issue${counts.medium > 1 ? 's' : ''}`);
    }
    if (counts.low > 0) {
      parts.push(`${counts.low} low severity issue${counts.low > 1 ? 's' : ''}`);
    }

    if (parts.length === 0) {
      return `${grade.description} security posture. No significant issues found.`;
    }

    return `${grade.description} security posture with ${parts.join(', ')}.`;
  }

  /**
   * Get recommendations based on findings
   */
  getRecommendations(grade, counts, findings) {
    const recommendations = [];

    // Critical issues
    if (counts.critical > 0) {
      recommendations.push({
        priority: 'immediate',
        action: 'Fix critical vulnerabilities before deploying',
        impact: 'Prevents potential security breaches'
      });
    }

    // Hardcoded secrets
    const hasSecrets = findings.some(f =>
      f.category === 'hardcodedSecrets' || f.title?.toLowerCase().includes('secret')
    );
    if (hasSecrets) {
      recommendations.push({
        priority: 'high',
        action: 'Move secrets to environment variables',
        impact: 'Prevents credential exposure in source control'
      });
    }

    // Injection vulnerabilities
    const hasInjection = findings.some(f =>
      f.category?.includes('injection') || f.title?.toLowerCase().includes('injection')
    );
    if (hasInjection) {
      recommendations.push({
        priority: 'high',
        action: 'Use parameterized queries and input validation',
        impact: 'Prevents SQL/NoSQL injection attacks'
      });
    }

    // Auth issues
    const hasAuthIssues = findings.some(f =>
      f.category === 'auth' || f.title?.toLowerCase().includes('auth')
    );
    if (hasAuthIssues) {
      recommendations.push({
        priority: 'high',
        action: 'Review and strengthen authentication implementation',
        impact: 'Prevents unauthorized access'
      });
    }

    // Dependency vulnerabilities
    const hasDependencyIssues = findings.some(f =>
      f.category === 'dependency' || f.category === 'live-cve'
    );
    if (hasDependencyIssues) {
      recommendations.push({
        priority: 'medium',
        action: 'Update vulnerable dependencies: npm update',
        impact: 'Patches known security vulnerabilities'
      });
    }

    // Grade-based general recommendations
    if (grade.letter === 'A') {
      recommendations.push({
        priority: 'maintenance',
        action: 'Set up automated security scanning in CI/CD',
        impact: 'Maintains excellent security posture'
      });
    } else if (grade.letter === 'B') {
      recommendations.push({
        priority: 'improvement',
        action: 'Address remaining medium/low issues for grade A',
        impact: 'Achieves excellent security posture'
      });
    } else {
      recommendations.push({
        priority: 'improvement',
        action: 'Run security-fix-tdd workflow to systematically address issues',
        impact: 'Improves overall security grade'
      });
    }

    return recommendations;
  }

  /**
   * Generate ASCII art score card
   */
  toAsciiCard(result) {
    const bar = this.generateProgressBar(result.score);

    return `
┌─────────────────────────────────────────────┐
│           SECURITY SCORE CARD               │
├─────────────────────────────────────────────┤
│                                             │
│      Grade: ${result.grade}  ${result.gradeEmoji}                          │
│      Score: ${result.score}/100                        │
│                                             │
│      ${bar}  │
│                                             │
├─────────────────────────────────────────────┤
│  Critical: ${String(result.breakdown.bySeverity.critical).padStart(3)}  │  High: ${String(result.breakdown.bySeverity.high).padStart(3)}            │
│  Medium:   ${String(result.breakdown.bySeverity.medium).padStart(3)}  │  Low:  ${String(result.breakdown.bySeverity.low).padStart(3)}            │
└─────────────────────────────────────────────┘
`.trim();
  }

  /**
   * Generate progress bar
   */
  generateProgressBar(score) {
    const filled = Math.round(score / 5);
    const empty = 20 - filled;
    return '[' + '█'.repeat(filled) + '░'.repeat(empty) + ']';
  }

  /**
   * Generate markdown report
   */
  toMarkdown(result) {
    let md = `# Security Score: ${result.grade} (${result.score}/100)\n\n`;
    md += `${result.summary}\n\n`;

    md += `## Breakdown\n\n`;
    md += `| Severity | Count |\n|----------|-------|\n`;
    for (const [sev, count] of Object.entries(result.breakdown.bySeverity)) {
      if (count > 0) {
        md += `| ${sev} | ${count} |\n`;
      }
    }
    md += `\n`;

    if (result.topIssues.length > 0) {
      md += `## Top Issues to Fix\n\n`;
      for (const issue of result.topIssues) {
        md += `- **[${issue.severity.toUpperCase()}]** ${issue.title}\n`;
        md += `  - Location: ${issue.location}\n`;
        md += `  - Quick fix: ${issue.quickFix}\n\n`;
      }
    }

    if (result.recommendations.length > 0) {
      md += `## Recommendations\n\n`;
      for (const rec of result.recommendations) {
        md += `- **[${rec.priority.toUpperCase()}]** ${rec.action}\n`;
        md += `  - Impact: ${rec.impact}\n\n`;
      }
    }

    return md;
  }
}

export default SecurityScoreCalculator;
