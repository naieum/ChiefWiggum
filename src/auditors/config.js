/**
 * Configuration Auditor
 *
 * Checks configuration files for security issues:
 * - Environment variable exposure
 * - Supabase RLS configuration
 * - Database connection security
 * - JWT configuration
 * - Package vulnerabilities
 */

import { readFile, access } from 'fs/promises';
import { join } from 'path';

export class ConfigAuditor {
  constructor(projectPath) {
    this.projectPath = projectPath;
    this.findings = [];
  }

  /**
   * Run all configuration audits
   */
  async audit() {
    this.findings = [];

    await Promise.all([
      this.auditEnvFiles(),
      this.auditSupabaseConfig(),
      this.auditPackageJson(),
      this.auditGitignore(),
      this.auditDockerConfig(),
    ]);

    return {
      findings: this.findings,
      summary: this.summarize()
    };
  }

  /**
   * Audit environment files for exposed secrets
   */
  async auditEnvFiles() {
    const envFiles = ['.env', '.env.local', '.env.production', '.env.development'];

    for (const envFile of envFiles) {
      const filePath = join(this.projectPath, envFile);

      try {
        await access(filePath);
        const content = await readFile(filePath, 'utf-8');

        // Check for common insecure patterns
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].trim();
          if (!line || line.startsWith('#')) continue;

          // Check for default/example values that shouldn't be in production
          if (/(?:password|secret|key)\s*=\s*(?:password|secret|123|example|test|changeme)/i.test(line)) {
            this.addFinding({
              severity: 'critical',
              title: 'Default/Weak Secret in Environment',
              description: `${envFile} contains a default or weak secret value.`,
              remediation: 'Replace default secrets with strong, unique values.',
              location: { file: envFile, line: i + 1, snippet: line.replace(/=.*/, '=***') }
            });
          }

          // Check for JWT secrets that are too short
          if (/JWT.*SECRET\s*=\s*(.{1,20})$/i.test(line)) {
            this.addFinding({
              severity: 'high',
              title: 'Weak JWT Secret',
              description: 'JWT secret appears to be less than 32 characters.',
              remediation: 'Use a JWT secret of at least 32 random characters.',
              location: { file: envFile, line: i + 1 }
            });
          }

          // Check for Supabase anon key exposure patterns
          if (/SUPABASE.*KEY.*=.*eyJ/i.test(line)) {
            this.addFinding({
              severity: 'info',
              title: 'Supabase Key in Environment',
              description: 'Supabase key detected. Ensure you have proper RLS policies.',
              remediation: 'Verify RLS is enabled on all tables and policies are correctly configured.',
              location: { file: envFile, line: i + 1 }
            });
          }
        }
      } catch {
        // File doesn't exist, skip
      }
    }
  }

  /**
   * Audit Supabase configuration
   */
  async auditSupabaseConfig() {
    // Check for Supabase config files
    const configPaths = [
      'supabase/config.toml',
      'supabase/.temp/config.toml',
    ];

    for (const configPath of configPaths) {
      try {
        const content = await readFile(join(this.projectPath, configPath), 'utf-8');

        // Check for disabled RLS
        if (/enable_rls\s*=\s*false/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Supabase RLS Disabled',
            description: 'Row Level Security is disabled in Supabase configuration.',
            remediation: 'Enable RLS and create appropriate policies for all tables.',
            location: { file: configPath }
          });
        }

        // Check for weak JWT settings
        if (/jwt_expiry\s*=\s*(\d+)/.test(content)) {
          const expiry = parseInt(RegExp.$1);
          if (expiry > 604800) { // More than 7 days
            this.addFinding({
              severity: 'medium',
              title: 'Long JWT Expiry',
              description: `JWT expiry is set to ${expiry} seconds (${Math.round(expiry / 86400)} days).`,
              remediation: 'Consider shorter JWT expiry times for better security.',
              location: { file: configPath }
            });
          }
        }
      } catch {
        // Config doesn't exist
      }
    }

    // Check for Supabase migration files with RLS issues
    try {
      const { readdir } = await import('fs/promises');
      const migrationsPath = join(this.projectPath, 'supabase/migrations');
      const files = await readdir(migrationsPath);

      for (const file of files) {
        if (!file.endsWith('.sql')) continue;

        const content = await readFile(join(migrationsPath, file), 'utf-8');

        // Check for CREATE TABLE without ENABLE ROW LEVEL SECURITY
        const tableMatches = content.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([^\s(]+)/gi);
        for (const match of tableMatches) {
          const tableName = match[1];
          const rlsPattern = new RegExp(`ALTER\\s+TABLE\\s+${tableName}\\s+ENABLE\\s+ROW\\s+LEVEL\\s+SECURITY`, 'i');
          if (!rlsPattern.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'Table Without RLS',
              description: `Table ${tableName} is created without enabling Row Level Security.`,
              remediation: `Add: ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;`,
              location: { file: `supabase/migrations/${file}` }
            });
          }
        }
      }
    } catch {
      // No migrations directory
    }
  }

  /**
   * Audit package.json for known vulnerable patterns
   */
  async auditPackageJson() {
    try {
      const content = await readFile(join(this.projectPath, 'package.json'), 'utf-8');
      const pkg = JSON.parse(content);
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

      // Check for packages with known security concerns
      const concerningPackages = {
        'node-serialize': 'Critical deserialization vulnerability',
        'serialize-javascript': 'Check version - older versions have XSS issues',
        'js-yaml': 'Check version - older versions have code execution issues',
        'lodash': 'Check version - older versions have prototype pollution',
        'minimist': 'Check version - older versions have prototype pollution',
        'express': 'Ensure version 4.17.3+ for security fixes',
      };

      for (const [pkg, concern] of Object.entries(concerningPackages)) {
        if (allDeps[pkg]) {
          this.addFinding({
            severity: 'medium',
            title: `Review Package: ${pkg}`,
            description: concern,
            remediation: `Run 'npm audit' and update ${pkg} to the latest secure version.`,
            location: { file: 'package.json' }
          });
        }
      }

      // Check for missing security-related scripts
      if (!pkg.scripts?.['audit'] && !pkg.scripts?.['security']) {
        this.addFinding({
          severity: 'info',
          title: 'No Security Audit Script',
          description: 'Consider adding a security audit script to package.json.',
          remediation: 'Add "audit": "npm audit" to your scripts for easy security checking.',
          location: { file: 'package.json' }
        });
      }
    } catch {
      // No package.json
    }
  }

  /**
   * Audit .gitignore for missing sensitive files
   */
  async auditGitignore() {
    try {
      const content = await readFile(join(this.projectPath, '.gitignore'), 'utf-8');

      const shouldIgnore = [
        { pattern: '.env', name: 'Environment files' },
        { pattern: '.env.local', name: 'Local environment files' },
        { pattern: '*.pem', name: 'Private keys' },
        { pattern: '*.key', name: 'Key files' },
        { pattern: 'credentials', name: 'Credentials directory' },
      ];

      for (const { pattern, name } of shouldIgnore) {
        if (!content.includes(pattern)) {
          this.addFinding({
            severity: 'high',
            title: `Missing Gitignore Entry: ${pattern}`,
            description: `${name} (${pattern}) should be in .gitignore to prevent accidental commits.`,
            remediation: `Add "${pattern}" to your .gitignore file.`,
            location: { file: '.gitignore' }
          });
        }
      }
    } catch {
      // No .gitignore - that's a finding itself
      this.addFinding({
        severity: 'high',
        title: 'Missing .gitignore',
        description: 'No .gitignore file found. Sensitive files may be committed.',
        remediation: 'Create a .gitignore file with entries for .env, *.key, *.pem, and other sensitive files.',
        location: { file: '.gitignore' }
      });
    }
  }

  /**
   * Audit Docker configuration
   */
  async auditDockerConfig() {
    try {
      const content = await readFile(join(this.projectPath, 'Dockerfile'), 'utf-8');

      // Check for running as root
      if (!content.includes('USER ') || content.includes('USER root')) {
        this.addFinding({
          severity: 'medium',
          title: 'Docker Container Runs as Root',
          description: 'Container may be running as root user.',
          remediation: 'Add a non-root USER directive to your Dockerfile.',
          location: { file: 'Dockerfile' }
        });
      }

      // Check for secrets in Dockerfile
      if (/(?:ARG|ENV)\s+(?:PASSWORD|SECRET|API_KEY|TOKEN)\s*=/i.test(content)) {
        this.addFinding({
          severity: 'critical',
          title: 'Secret in Dockerfile',
          description: 'Secrets should not be hardcoded in Dockerfiles.',
          remediation: 'Use Docker secrets or environment variables at runtime instead.',
          location: { file: 'Dockerfile' }
        });
      }

      // Check for latest tag
      if (/:latest/g.test(content)) {
        this.addFinding({
          severity: 'low',
          title: 'Using :latest Tag',
          description: 'Using :latest tag can lead to unpredictable builds.',
          remediation: 'Pin to specific version tags for reproducible builds.',
          location: { file: 'Dockerfile' }
        });
      }
    } catch {
      // No Dockerfile
    }

    // Check docker-compose
    try {
      const content = await readFile(join(this.projectPath, 'docker-compose.yml'), 'utf-8');

      if (/privileged:\s*true/i.test(content)) {
        this.addFinding({
          severity: 'high',
          title: 'Privileged Container',
          description: 'Container is running in privileged mode.',
          remediation: 'Avoid privileged mode. Use specific capabilities instead.',
          location: { file: 'docker-compose.yml' }
        });
      }
    } catch {
      // No docker-compose
    }
  }

  /**
   * Add a finding
   */
  addFinding(finding) {
    this.findings.push({
      category: 'configuration',
      ...finding
    });
  }

  /**
   * Generate summary
   */
  summarize() {
    const summary = {
      total: this.findings.length,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    };

    for (const finding of this.findings) {
      summary.bySeverity[finding.severity]++;
    }

    return summary;
  }
}

export default ConfigAuditor;
