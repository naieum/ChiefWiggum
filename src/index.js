/**
 * Guardian-Agent: Defensive Security Scanner for Claude Code
 *
 * This plugin helps developers find and fix security vulnerabilities
 * in their OWN projects. It is designed for self-assessment, not
 * for testing systems you don't own.
 *
 * Modules:
 * - Static Analysis: Scans source code for vulnerability patterns
 * - Config Auditor: Checks configuration files for security issues
 * - Safe Checks: Non-destructive tests against localhost only
 * - Reporter: Generates actionable security reports
 */

import { StaticAnalyzer } from './analyzers/static.js';
import { ConfigAuditor } from './auditors/config.js';
import { SafeChecker } from './auditors/safe-checks.js';
import { Reporter } from './reporters/json-reporter.js';

export class GuardianAgent {
  constructor(projectPath, options = {}) {
    this.projectPath = projectPath;
    this.options = {
      // Only allow testing localhost by default
      allowedHosts: ['localhost', '127.0.0.1'],
      // Restrict dynamic tests to development environments
      requireDevEnvironment: true,
      // Output format
      reportFormat: 'json',
      ...options
    };

    this.staticAnalyzer = new StaticAnalyzer(projectPath);
    this.configAuditor = new ConfigAuditor(projectPath);
    this.safeChecker = new SafeChecker(this.options);
    this.reporter = new Reporter();

    this.findings = [];
  }

  /**
   * Run a full security scan on the project
   */
  async runFullScan() {
    console.log('🛡️  Guardian-Agent Security Scan');
    console.log('================================\n');

    const results = {
      timestamp: new Date().toISOString(),
      projectPath: this.projectPath,
      phases: {}
    };

    // Phase 1: Static Analysis (always safe - just reads code)
    console.log('📋 Phase 1: Static Analysis...');
    results.phases.staticAnalysis = await this.staticAnalyzer.analyze();

    // Phase 2: Configuration Audit (reads config files)
    console.log('⚙️  Phase 2: Configuration Audit...');
    results.phases.configAudit = await this.configAuditor.audit();

    // Phase 3: Safe Dynamic Checks (localhost only, non-destructive)
    console.log('🔍 Phase 3: Safe Checks...');
    results.phases.safeChecks = await this.safeChecker.runChecks();

    // Compile findings
    this.findings = [
      ...results.phases.staticAnalysis.findings,
      ...results.phases.configAudit.findings,
      ...results.phases.safeChecks.findings
    ];

    // Generate report
    console.log('\n📊 Generating Report...');
    results.report = this.reporter.generate(this.findings);

    return results;
  }

  /**
   * Run only static analysis (zero network activity)
   */
  async runStaticOnly() {
    return await this.staticAnalyzer.analyze();
  }

  /**
   * Run only config audit (zero network activity)
   */
  async runConfigAuditOnly() {
    return await this.configAuditor.audit();
  }
}

// CLI entry point
if (import.meta.url === `file://${process.argv[1]}`) {
  const projectPath = process.argv[2] || process.cwd();
  const agent = new GuardianAgent(projectPath);

  agent.runFullScan()
    .then(results => {
      console.log('\n✅ Scan complete!');
      console.log(JSON.stringify(results.report, null, 2));
    })
    .catch(err => {
      console.error('❌ Scan failed:', err.message);
      process.exit(1);
    });
}

export default GuardianAgent;
