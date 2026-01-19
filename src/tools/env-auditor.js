/**
 * Environment File Auditor
 *
 * Checks .env files for security issues:
 * - Exposed secrets
 * - Missing from .gitignore
 * - Insecure patterns
 * - Missing required variables
 */

import { readFile, readdir, access } from 'fs/promises';
import { join, basename } from 'path';

export class EnvAuditor {
  constructor(projectPath) {
    this.projectPath = projectPath;
    this.findings = [];
  }

  /**
   * Common secret patterns to detect
   */
  static SECRET_PATTERNS = [
    { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/, severity: 'critical' },
    { name: 'AWS Secret Key', pattern: /[A-Za-z0-9/+=]{40}/, context: 'aws', severity: 'critical' },
    { name: 'GitHub Token', pattern: /gh[ps]_[A-Za-z0-9_]{36,}/, severity: 'critical' },
    { name: 'GitHub OAuth', pattern: /gho_[A-Za-z0-9_]{36,}/, severity: 'critical' },
    { name: 'Slack Token', pattern: /xox[baprs]-[0-9A-Za-z-]+/, severity: 'critical' },
    { name: 'Stripe Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/, severity: 'critical' },
    { name: 'Stripe Test Key', pattern: /sk_test_[0-9a-zA-Z]{24,}/, severity: 'medium' },
    { name: 'Private Key', pattern: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/, severity: 'critical' },
    { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/, severity: 'high' },
    { name: 'Firebase Key', pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/, severity: 'high' },
    { name: 'Twilio Key', pattern: /SK[0-9a-fA-F]{32}/, severity: 'high' },
    { name: 'SendGrid Key', pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/, severity: 'high' },
    { name: 'Mailgun Key', pattern: /key-[0-9a-zA-Z]{32}/, severity: 'high' },
    { name: 'JWT Secret', pattern: /^[A-Za-z0-9+/=]{32,}$/, context: 'jwt', severity: 'high' },
    { name: 'Database URL', pattern: /(?:postgres|mysql|mongodb):\/\/[^:]+:[^@]+@/, severity: 'critical' },
    { name: 'Supabase Service Key', pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, context: 'supabase_service', severity: 'critical' },
    { name: 'OpenAI Key', pattern: /sk-[A-Za-z0-9]{48}/, severity: 'high' },
    { name: 'Anthropic Key', pattern: /sk-ant-[A-Za-z0-9_-]+/, severity: 'high' },
  ];

  /**
   * Variables that should NEVER be in .env files committed to git
   */
  static NEVER_COMMIT = [
    'DATABASE_URL',
    'DATABASE_PASSWORD',
    'DB_PASSWORD',
    'SECRET_KEY',
    'JWT_SECRET',
    'SESSION_SECRET',
    'ENCRYPTION_KEY',
    'PRIVATE_KEY',
    'AWS_SECRET_ACCESS_KEY',
    'SUPABASE_SERVICE_ROLE_KEY',
    'STRIPE_SECRET_KEY',
    'SENDGRID_API_KEY',
    'OPENAI_API_KEY',
    'ANTHROPIC_API_KEY',
  ];

  /**
   * Run full environment audit
   */
  async audit() {
    console.error('[EnvAudit] Auditing environment files...');

    // Find all .env files
    const envFiles = await this.findEnvFiles();
    console.error(`[EnvAudit] Found ${envFiles.length} environment files`);

    // Check .gitignore
    const gitignoreIssues = await this.checkGitignore(envFiles);
    this.findings.push(...gitignoreIssues);

    // Audit each file
    for (const envFile of envFiles) {
      const fileIssues = await this.auditEnvFile(envFile);
      this.findings.push(...fileIssues);
    }

    // Check for missing .env.example
    const exampleIssues = await this.checkEnvExample(envFiles);
    this.findings.push(...exampleIssues);

    // Check for proper .env usage in code
    const usageIssues = await this.checkEnvUsage();
    this.findings.push(...usageIssues);

    return {
      findings: this.findings,
      filesAudited: envFiles.length,
      summary: this.generateSummary()
    };
  }

  /**
   * Find all .env files in project
   */
  async findEnvFiles() {
    const envFiles = [];
    const patterns = [
      '.env',
      '.env.local',
      '.env.development',
      '.env.development.local',
      '.env.production',
      '.env.production.local',
      '.env.test',
      '.env.test.local',
      '.env.staging',
    ];

    for (const pattern of patterns) {
      try {
        await access(join(this.projectPath, pattern));
        envFiles.push(pattern);
      } catch {
        // File doesn't exist
      }
    }

    return envFiles;
  }

  /**
   * Check if env files are properly gitignored
   */
  async checkGitignore(envFiles) {
    const findings = [];

    try {
      const gitignore = await readFile(join(this.projectPath, '.gitignore'), 'utf-8');
      const gitignoreLines = gitignore.split('\n').map(l => l.trim());

      // Check each env file
      for (const envFile of envFiles) {
        // Skip .env.example - it should be committed
        if (envFile.includes('example')) continue;

        const isIgnored = gitignoreLines.some(line => {
          if (line.startsWith('#') || !line) return false;
          // Check exact match or pattern match
          if (line === envFile) return true;
          if (line === '.env*' || line === '.env.*') return true;
          if (line === '*.local' && envFile.endsWith('.local')) return true;
          return false;
        });

        if (!isIgnored) {
          findings.push({
            severity: 'critical',
            title: `${envFile} not in .gitignore`,
            description: `The file ${envFile} contains sensitive data but is not gitignored. It may be committed to version control.`,
            category: 'env-security',
            location: { file: envFile },
            remediation: `Add "${envFile}" to .gitignore immediately. If already committed, remove from git history and rotate all secrets.`
          });
        }
      }

      // Check for general .env pattern
      const hasEnvPattern = gitignoreLines.some(line =>
        line === '.env*' || line === '.env' || line === '.env.*'
      );
      if (!hasEnvPattern && envFiles.length > 0) {
        findings.push({
          severity: 'high',
          title: 'Missing general .env pattern in .gitignore',
          description: 'Consider adding ".env*" to .gitignore to catch all environment files.',
          category: 'env-security',
          location: { file: '.gitignore' },
          remediation: 'Add ".env*" to .gitignore to prevent accidental commits of any env file.'
        });
      }

    } catch {
      findings.push({
        severity: 'high',
        title: 'No .gitignore file found',
        description: 'Project has no .gitignore file. Environment files may be committed to version control.',
        category: 'env-security',
        location: { file: '.gitignore' },
        remediation: 'Create a .gitignore file and add ".env*" to prevent committing secrets.'
      });
    }

    return findings;
  }

  /**
   * Audit a single .env file
   */
  async auditEnvFile(envFile) {
    const findings = [];

    try {
      const content = await readFile(join(this.projectPath, envFile), 'utf-8');
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();

        // Skip comments and empty lines
        if (!line || line.startsWith('#')) continue;

        // Parse key=value
        const match = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/i);
        if (!match) continue;

        const [, key, value] = match;

        // Check for empty values (might indicate missing config)
        if (!value || value === '""' || value === "''") {
          findings.push({
            severity: 'info',
            title: `Empty value for ${key}`,
            description: `${envFile}:${i + 1} - ${key} has an empty value.`,
            category: 'env-config',
            location: { file: envFile, line: i + 1 },
            remediation: 'Ensure this variable has a proper value in production.'
          });
          continue;
        }

        // Check for placeholder values
        if (this.isPlaceholder(value)) {
          findings.push({
            severity: 'medium',
            title: `Placeholder value for ${key}`,
            description: `${envFile}:${i + 1} - ${key} appears to have a placeholder value: "${value}"`,
            category: 'env-config',
            location: { file: envFile, line: i + 1 },
            remediation: 'Replace placeholder with actual value before deployment.'
          });
          continue;
        }

        // Check for secret patterns
        for (const { name, pattern, severity, context } of EnvAuditor.SECRET_PATTERNS) {
          if (pattern.test(value)) {
            // Skip if context doesn't match
            if (context && !key.toLowerCase().includes(context)) continue;

            findings.push({
              severity,
              title: `Potential ${name} found in ${envFile}`,
              description: `${envFile}:${i + 1} - ${key} appears to contain a ${name}.`,
              category: 'env-secrets',
              location: { file: envFile, line: i + 1, key },
              remediation: `Ensure this file is not committed to version control. Rotate this secret if exposed.`
            });
          }
        }

        // Check for sensitive variable names with real values
        if (this.isSensitiveKey(key) && !this.isPlaceholder(value)) {
          // Only warn if file might be committed
          if (!envFile.includes('.local') && !envFile.includes('.example')) {
            findings.push({
              severity: 'high',
              title: `Sensitive variable ${key} with real value`,
              description: `${envFile}:${i + 1} - ${key} appears to contain a real secret value.`,
              category: 'env-secrets',
              location: { file: envFile, line: i + 1, key },
              remediation: `Move to .env.local (gitignored) or use a secrets manager.`
            });
          }
        }
      }

    } catch (err) {
      // File read error
      console.error(`[EnvAudit] Error reading ${envFile}: ${err.message}`);
    }

    return findings;
  }

  /**
   * Check for .env.example
   */
  async checkEnvExample(envFiles) {
    const findings = [];

    const hasEnvExample = envFiles.some(f => f.includes('example'));

    if (!hasEnvExample && envFiles.length > 0) {
      findings.push({
        severity: 'low',
        title: 'Missing .env.example file',
        description: 'No .env.example file found. This file helps developers know which environment variables are needed.',
        category: 'env-config',
        location: { file: '.env.example' },
        remediation: 'Create .env.example with all required variables (using placeholder values) and commit to version control.'
      });
    }

    return findings;
  }

  /**
   * Check for proper env usage in code
   */
  async checkEnvUsage() {
    const findings = [];

    // Check if dotenv is used properly
    try {
      const pkg = JSON.parse(await readFile(join(this.projectPath, 'package.json'), 'utf-8'));
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };

      if (!deps.dotenv && !deps['@next/env'] && !deps['vite']) {
        findings.push({
          severity: 'info',
          title: 'No dotenv package detected',
          description: 'Project may not be loading environment variables. Consider using dotenv or a framework with built-in env support.',
          category: 'env-config',
          location: { file: 'package.json' },
          remediation: 'Install dotenv: npm install dotenv, then require it early in your app.'
        });
      }
    } catch {
      // No package.json
    }

    return findings;
  }

  /**
   * Check if value looks like a placeholder
   */
  isPlaceholder(value) {
    const placeholders = [
      /^your[_-]?.*$/i,
      /^xxx+$/i,
      /^<.*>$/,
      /^\[.*\]$/,
      /^{.*}$/,
      /^placeholder/i,
      /^changeme/i,
      /^todo/i,
      /^fixme/i,
      /^example/i,
      /^test$/i,
      /^dummy/i,
    ];

    return placeholders.some(p => p.test(value));
  }

  /**
   * Check if key is likely sensitive
   */
  isSensitiveKey(key) {
    const sensitive = [
      'SECRET', 'KEY', 'TOKEN', 'PASSWORD', 'CREDENTIAL',
      'AUTH', 'API_KEY', 'PRIVATE', 'ACCESS', 'ENCRYPTION'
    ];

    const keyUpper = key.toUpperCase();
    return sensitive.some(s => keyUpper.includes(s));
  }

  /**
   * Generate summary
   */
  generateSummary() {
    const critical = this.findings.filter(f => f.severity === 'critical').length;
    const high = this.findings.filter(f => f.severity === 'high').length;

    if (critical > 0) {
      return `CRITICAL: Found ${critical} critical and ${high} high severity issues in environment files. Immediate action required.`;
    }
    if (high > 0) {
      return `WARNING: Found ${high} high severity issues in environment files. Review and fix before deployment.`;
    }
    if (this.findings.length > 0) {
      return `Found ${this.findings.length} issues in environment files. Review recommendations.`;
    }
    return 'Environment files passed security audit.';
  }

  /**
   * Generate .env.example from existing .env
   */
  async generateEnvExample() {
    const envFiles = await this.findEnvFiles();
    const mainEnv = envFiles.find(f => f === '.env' || f === '.env.local') || envFiles[0];

    if (!mainEnv) {
      return { error: 'No .env file found to generate example from.' };
    }

    try {
      const content = await readFile(join(this.projectPath, mainEnv), 'utf-8');
      const lines = content.split('\n');
      const exampleLines = [];

      for (const line of lines) {
        const trimmed = line.trim();

        // Keep comments
        if (trimmed.startsWith('#') || !trimmed) {
          exampleLines.push(line);
          continue;
        }

        // Parse and mask
        const match = trimmed.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/i);
        if (match) {
          const [, key, value] = match;
          const placeholder = this.generatePlaceholder(key, value);
          exampleLines.push(`${key}=${placeholder}`);
        } else {
          exampleLines.push(line);
        }
      }

      return {
        content: exampleLines.join('\n'),
        sourceFile: mainEnv
      };
    } catch (err) {
      return { error: `Failed to read ${mainEnv}: ${err.message}` };
    }
  }

  /**
   * Generate appropriate placeholder for a key
   */
  generatePlaceholder(key, value) {
    const keyLower = key.toLowerCase();

    if (keyLower.includes('url')) return 'https://example.com';
    if (keyLower.includes('port')) return '3000';
    if (keyLower.includes('host')) return 'localhost';
    if (keyLower.includes('email')) return 'your@email.com';
    if (keyLower.includes('secret') || keyLower.includes('key')) return 'your-secret-here';
    if (keyLower.includes('token')) return 'your-token-here';
    if (keyLower.includes('password')) return 'your-password-here';
    if (keyLower.includes('id')) return 'your-id-here';
    if (keyLower.includes('name')) return 'your-name-here';
    if (value === 'true' || value === 'false') return value;
    if (/^\d+$/.test(value)) return value; // Keep numbers

    return 'your-value-here';
  }
}

export default EnvAuditor;
