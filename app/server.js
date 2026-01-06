#!/usr/bin/env node

/**
 * Guardian-Agent MCP Server
 *
 * This is the MCP (Model Context Protocol) server that handles tool calls
 * from Claude Code. It provides security scanning capabilities scoped to
 * the user's local project only.
 */

import { createServer } from 'http';
import { readFile, readdir, stat } from 'fs/promises';
import { join, extname, resolve } from 'path';

// Import our scanner modules
import { StaticAnalyzer } from '../src/analyzers/static.js';
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

    this.staticAnalyzer = new StaticAnalyzer(this.projectPath);
    this.configAuditor = new ConfigAuditor(this.projectPath);
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
      case 'scan_project_security':
        return await this.scanProjectSecurity(params);

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
   * Scan project source code for vulnerabilities
   */
  async scanProjectSecurity(params = {}) {
    const scanType = params.scan_type || 'full';
    const filePatterns = params.file_patterns || ['**/*.js', '**/*.ts', '**/*.py'];

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
    } else if (scanType === 'config') {
      // Run config audit instead
      const configResults = await this.configAuditor.audit();
      filteredFindings = configResults.findings;
    }

    // Store for report generation
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
      summary: {
        critical: filteredFindings.filter(f => f.severity === 'critical').length,
        high: filteredFindings.filter(f => f.severity === 'high').length,
        medium: filteredFindings.filter(f => f.severity === 'medium').length,
        low: filteredFindings.filter(f => f.severity === 'low').length
      }
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
      if (detectedType === 'supabase') {
        return f.title.toLowerCase().includes('supabase') ||
               f.title.toLowerCase().includes('rls') ||
               f.title.toLowerCase().includes('jwt');
      }
      if (detectedType === 'mongodb') {
        return f.title.toLowerCase().includes('mongo') ||
               f.title.toLowerCase().includes('nosql');
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
      return {
        success: true,
        format: 'json',
        report: report
      };
    }

    if (format === 'markdown') {
      return {
        success: true,
        format: 'markdown',
        report: this.reporter.toMarkdown(report)
      };
    }

    // SARIF format for IDE integration
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
      const packageJson = await readFile(
        join(this.projectPath, 'package.json'),
        'utf-8'
      );
      const pkg = JSON.parse(packageJson);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };

      if (deps['@supabase/supabase-js']) return 'supabase';
      if (deps['mongoose'] || deps['mongodb']) return 'mongodb';
      if (deps['pg'] || deps['postgres']) return 'postgres';
      if (deps['prisma'] || deps['@prisma/client']) return 'prisma';

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
        'Use short JWT expiry times',
        'Validate user input before database operations'
      ],
      mongodb: [
        'Enable authentication on your MongoDB instance',
        'Use parameterized queries to prevent injection',
        'Sanitize user input - watch for $where and $regex operators',
        'Implement field-level encryption for sensitive data',
        'Use MongoDB Atlas with network access controls'
      ],
      postgres: [
        'Use parameterized queries ($1, $2 placeholders)',
        'Implement row-level security policies',
        'Use least-privilege database roles',
        'Enable SSL for database connections',
        'Regularly audit database access logs'
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
   * Convert report to SARIF format (for IDE integration)
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
          locations: f.location.file ? [{
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
 * Reads JSON-RPC messages from stdin, processes them, writes responses to stdout
 */
async function main() {
  const server = new GuardianMCPServer();

  // Simple JSON-RPC over stdio
  process.stdin.setEncoding('utf-8');

  let buffer = '';

  process.stdin.on('data', async (chunk) => {
    buffer += chunk;

    // Try to parse complete JSON messages
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
                  name: 'scan_project_security',
                  description: 'Scans the current project for security vulnerabilities',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      scan_type: { type: 'string', enum: ['full', 'secrets', 'injection', 'config'] },
                      file_patterns: { type: 'array', items: { type: 'string' } }
                    }
                  }
                },
                {
                  name: 'audit_database_config',
                  description: 'Audits database configuration for security issues',
                  inputSchema: {
                    type: 'object',
                    properties: {
                      db_type: { type: 'string', enum: ['postgres', 'supabase', 'mongodb', 'auto'] }
                    }
                  }
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
                  description: 'Generates a formatted security report',
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
