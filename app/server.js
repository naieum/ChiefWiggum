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
import { ConfigAuditor } from '../src/auditors/config.js';
import { SafeChecker } from '../src/auditors/safe-checks.js';
import { Reporter } from '../src/reporters/json-reporter.js';

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

      default:
        return { error: `Unknown tool: ${toolName}` };
    }
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
