/**
 * Guardian-Agent: Comprehensive Defensive Security Scanner for Claude Code
 *
 * This plugin helps developers find and fix security vulnerabilities
 * in their OWN projects. It is designed for self-assessment, not
 * for testing systems you don't own.
 *
 * Modules:
 * - Stack Detector: Identifies all technologies in the project
 * - Static Analysis: Scans source code for vulnerability patterns
 * - Framework Security: Framework-specific security checks
 * - Database Security: Database-specific deep checks
 * - Auth Security: Authentication and session security
 * - API Security: API endpoint security analysis
 * - Dependency Security: Checks for vulnerable packages
 * - Config Auditor: Checks configuration files for security issues
 * - Safe Checks: Non-destructive tests against localhost only
 * - Reporter: Generates actionable security reports
 */

import { StackDetector } from './analyzers/stack-detector.js';
import { StaticAnalyzer } from './analyzers/static.js';
import { FrameworkSecurityAnalyzer } from './analyzers/framework-security.js';
import { DatabaseSecurityAnalyzer } from './analyzers/database-security.js';
import { AuthSecurityAnalyzer } from './analyzers/auth-security.js';
import { APISecurityAnalyzer } from './analyzers/api-security.js';
import { DependencySecurityAnalyzer } from './analyzers/dependency-security.js';
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
      // Run all analyzers by default
      analyzers: {
        stack: true,
        static: true,
        framework: true,
        database: true,
        auth: true,
        api: true,
        dependencies: true,
        config: true,
        safeChecks: true,
      },
      ...options
    };

    this.stackDetector = new StackDetector(projectPath);
    this.staticAnalyzer = new StaticAnalyzer(projectPath);
    this.configAuditor = new ConfigAuditor(projectPath);
    this.dependencyAnalyzer = new DependencySecurityAnalyzer(projectPath);
    this.safeChecker = new SafeChecker(this.options);
    this.reporter = new Reporter();

    this.detectedStack = null;
    this.findings = [];
  }

  /**
   * Run a full comprehensive security scan on the project
   */
  async runFullScan() {
    console.log('🛡️  Guardian-Agent Comprehensive Security Scan');
    console.log('==============================================\n');

    const results = {
      timestamp: new Date().toISOString(),
      projectPath: this.projectPath,
      stack: null,
      phases: {}
    };

    // Phase 0: Stack Detection (identifies all technologies)
    console.log('🔍 Phase 0: Detecting Tech Stack...');
    const stackResult = await this.stackDetector.detect();
    this.detectedStack = stackResult.stack;
    results.stack = stackResult;
    console.log(`   Found: ${stackResult.summary.text || 'No specific stack detected'}\n`);

    // Phase 1: Dependency Security (check for vulnerable packages)
    if (this.options.analyzers.dependencies) {
      console.log('📦 Phase 1: Dependency Security Analysis...');
      results.phases.dependencies = await this.dependencyAnalyzer.analyze();
      console.log(`   Found ${results.phases.dependencies.findings.length} dependency issues\n`);
    }

    // Phase 2: Static Analysis (general vulnerability patterns)
    if (this.options.analyzers.static) {
      console.log('📋 Phase 2: Static Code Analysis...');
      results.phases.staticAnalysis = await this.staticAnalyzer.analyze();
      console.log(`   Found ${results.phases.staticAnalysis.findings.length} code issues\n`);
    }

    // Phase 3: Framework-Specific Security
    if (this.options.analyzers.framework) {
      console.log('⚙️  Phase 3: Framework-Specific Security...');
      const frameworkAnalyzer = new FrameworkSecurityAnalyzer(this.projectPath, this.detectedStack);
      results.phases.framework = await frameworkAnalyzer.analyze();
      console.log(`   Found ${results.phases.framework.findings.length} framework issues\n`);
    }

    // Phase 4: Database Security
    if (this.options.analyzers.database && this.detectedStack.database?.length > 0) {
      console.log('🗄️  Phase 4: Database Security Analysis...');
      const dbAnalyzer = new DatabaseSecurityAnalyzer(this.projectPath, this.detectedStack);
      results.phases.database = await dbAnalyzer.analyze();
      console.log(`   Found ${results.phases.database.findings.length} database issues\n`);
    }

    // Phase 5: Authentication Security
    if (this.options.analyzers.auth && this.detectedStack.auth?.length > 0) {
      console.log('🔐 Phase 5: Authentication Security Analysis...');
      const authAnalyzer = new AuthSecurityAnalyzer(this.projectPath, this.detectedStack);
      results.phases.auth = await authAnalyzer.analyze();
      console.log(`   Found ${results.phases.auth.findings.length} auth issues\n`);
    }

    // Phase 6: API Security
    if (this.options.analyzers.api && this.detectedStack.api?.length > 0) {
      console.log('🌐 Phase 6: API Security Analysis...');
      const apiAnalyzer = new APISecurityAnalyzer(this.projectPath, this.detectedStack);
      results.phases.api = await apiAnalyzer.analyze();
      console.log(`   Found ${results.phases.api.findings.length} API issues\n`);
    }

    // Phase 7: Configuration Audit
    if (this.options.analyzers.config) {
      console.log('📝 Phase 7: Configuration Audit...');
      results.phases.configAudit = await this.configAuditor.audit();
      console.log(`   Found ${results.phases.configAudit.findings.length} config issues\n`);
    }

    // Phase 8: Safe Dynamic Checks (localhost only)
    if (this.options.analyzers.safeChecks) {
      console.log('🔍 Phase 8: Safe Dynamic Checks (localhost only)...');
      results.phases.safeChecks = await this.safeChecker.runChecks();
      console.log(`   Found ${results.phases.safeChecks.findings?.length || 0} header issues\n`);
    }

    // Compile all findings
    this.findings = [];
    for (const phase of Object.values(results.phases)) {
      if (phase && phase.findings) {
        this.findings.push(...phase.findings);
      }
    }

    // Deduplicate findings
    this.findings = this.deduplicateFindings(this.findings);

    // Generate report
    console.log('📊 Generating Report...');
    results.report = this.reporter.generate(this.findings);

    // Print summary
    this.printSummary(results.report);

    return results;
  }

  /**
   * Run quick scan (just static + deps)
   */
  async runQuickScan() {
    console.log('🛡️  Guardian-Agent Quick Security Scan\n');

    const results = {
      timestamp: new Date().toISOString(),
      projectPath: this.projectPath,
      phases: {}
    };

    // Static analysis
    console.log('📋 Running static analysis...');
    results.phases.staticAnalysis = await this.staticAnalyzer.analyze();

    // Dependency check
    console.log('📦 Checking dependencies...');
    results.phases.dependencies = await this.dependencyAnalyzer.analyze();

    this.findings = [
      ...results.phases.staticAnalysis.findings,
      ...results.phases.dependencies.findings
    ];

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

  /**
   * Detect tech stack
   */
  async detectStack() {
    return await this.stackDetector.detect();
  }

  /**
   * Run database-specific security checks
   */
  async runDatabaseScan() {
    if (!this.detectedStack) {
      const stackResult = await this.stackDetector.detect();
      this.detectedStack = stackResult.stack;
    }

    const dbAnalyzer = new DatabaseSecurityAnalyzer(this.projectPath, this.detectedStack);
    return await dbAnalyzer.analyze();
  }

  /**
   * Run auth-specific security checks
   */
  async runAuthScan() {
    if (!this.detectedStack) {
      const stackResult = await this.stackDetector.detect();
      this.detectedStack = stackResult.stack;
    }

    const authAnalyzer = new AuthSecurityAnalyzer(this.projectPath, this.detectedStack);
    return await authAnalyzer.analyze();
  }

  /**
   * Run API security checks
   */
  async runAPIScan() {
    if (!this.detectedStack) {
      const stackResult = await this.stackDetector.detect();
      this.detectedStack = stackResult.stack;
    }

    const apiAnalyzer = new APISecurityAnalyzer(this.projectPath, this.detectedStack);
    return await apiAnalyzer.analyze();
  }

  /**
   * Deduplicate findings with same title and location
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
   * Print summary to console
   */
  printSummary(report) {
    console.log('\n════════════════════════════════════════');
    console.log('               SCAN SUMMARY              ');
    console.log('════════════════════════════════════════\n');

    const { summary } = report;

    console.log(`Total Findings: ${summary.totalFindings}`);
    console.log(`Risk Score: ${summary.riskScore}/100 (${summary.riskLevel})\n`);

    console.log('By Severity:');
    console.log(`  🔴 Critical: ${summary.bySeverity.critical}`);
    console.log(`  🟠 High:     ${summary.bySeverity.high}`);
    console.log(`  🟡 Medium:   ${summary.bySeverity.medium}`);
    console.log(`  🔵 Low:      ${summary.bySeverity.low}`);
    console.log(`  ⚪ Info:     ${summary.bySeverity.info}`);

    if (summary.bySeverity.critical > 0) {
      console.log('\n⚠️  CRITICAL ISSUES REQUIRE IMMEDIATE ATTENTION');
    }

    console.log('\n════════════════════════════════════════\n');
  }
}

// CLI entry point
if (import.meta.url === `file://${process.argv[1]}`) {
  const projectPath = process.argv[2] || process.cwd();
  const scanType = process.argv[3] || 'full';

  const agent = new GuardianAgent(projectPath);

  let scanPromise;
  switch (scanType) {
    case 'quick':
      scanPromise = agent.runQuickScan();
      break;
    case 'static':
      scanPromise = agent.runStaticOnly();
      break;
    case 'database':
      scanPromise = agent.runDatabaseScan();
      break;
    case 'auth':
      scanPromise = agent.runAuthScan();
      break;
    case 'api':
      scanPromise = agent.runAPIScan();
      break;
    default:
      scanPromise = agent.runFullScan();
  }

  scanPromise
    .then(results => {
      console.log('✅ Scan complete!');
      if (results.report) {
        console.log(JSON.stringify(results.report, null, 2));
      } else {
        console.log(JSON.stringify(results, null, 2));
      }
    })
    .catch(err => {
      console.error('❌ Scan failed:', err.message);
      console.error(err.stack);
      process.exit(1);
    });
}

export default GuardianAgent;
