/**
 * Dependency Security Analyzer
 *
 * Checks for security issues in project dependencies:
 * - Known vulnerable packages
 * - Outdated packages with security patches
 * - Risky package patterns
 * - Typosquatting risks
 * - Supply chain concerns
 */

import { readFile, access } from 'fs/promises';
import { join } from 'path';

export class DependencySecurityAnalyzer {
  constructor(projectPath) {
    this.projectPath = projectPath;
    this.findings = [];
  }

  /**
   * Known vulnerable packages and patterns
   * This is a subset - in production, you'd integrate with npm audit / OSV
   */
  static KNOWN_VULNERABILITIES = {
    // Critical - actively exploited or severe
    'node-serialize': {
      severity: 'critical',
      reason: 'Arbitrary code execution via deserialization',
      remediation: 'Remove package. Use safe-serialize or built-in JSON.'
    },
    'serialize-to-js': {
      severity: 'critical',
      reason: 'Code injection vulnerability',
      remediation: 'Remove and use JSON.stringify instead.'
    },
    'flat': {
      severity: 'high',
      versions: '<5.0.1',
      reason: 'Prototype pollution (CVE-2020-36632)',
      remediation: 'Update to flat@5.0.1 or later.'
    },
    'minimist': {
      severity: 'high',
      versions: '<1.2.6',
      reason: 'Prototype pollution (CVE-2021-44906)',
      remediation: 'Update to minimist@1.2.6 or later.'
    },
    'lodash': {
      severity: 'high',
      versions: '<4.17.21',
      reason: 'Prototype pollution (CVE-2021-23337)',
      remediation: 'Update to lodash@4.17.21 or later.'
    },
    'axios': {
      severity: 'high',
      versions: '<0.21.2',
      reason: 'Server-Side Request Forgery (CVE-2021-3749)',
      remediation: 'Update to axios@0.21.2 or later.'
    },
    'glob-parent': {
      severity: 'high',
      versions: '<5.1.2',
      reason: 'ReDoS vulnerability (CVE-2020-28469)',
      remediation: 'Update to glob-parent@5.1.2 or later.'
    },
    'path-parse': {
      severity: 'medium',
      versions: '<1.0.7',
      reason: 'ReDoS vulnerability (CVE-2021-23343)',
      remediation: 'Update to path-parse@1.0.7 or later.'
    },
    'node-fetch': {
      severity: 'medium',
      versions: '<2.6.7',
      reason: 'Exposure of sensitive information (CVE-2022-0235)',
      remediation: 'Update to node-fetch@2.6.7 or later.'
    },
    'jsonwebtoken': {
      severity: 'high',
      versions: '<9.0.0',
      reason: 'Various security vulnerabilities',
      remediation: 'Update to jsonwebtoken@9.0.0 or later.'
    },
    'express': {
      severity: 'medium',
      versions: '<4.17.3',
      reason: 'Open redirect vulnerability',
      remediation: 'Update to express@4.17.3 or later.'
    },
    'qs': {
      severity: 'high',
      versions: '<6.10.3',
      reason: 'Prototype pollution (CVE-2022-24999)',
      remediation: 'Update to qs@6.10.3 or later.'
    },
    'async': {
      severity: 'high',
      versions: '<3.2.2',
      reason: 'Prototype pollution (CVE-2021-43138)',
      remediation: 'Update to async@3.2.2 or later.'
    },
    'ansi-regex': {
      severity: 'medium',
      versions: '<5.0.1',
      reason: 'ReDoS vulnerability (CVE-2021-3807)',
      remediation: 'Update to ansi-regex@5.0.1 or later.'
    },
    'highlight.js': {
      severity: 'medium',
      versions: '<10.4.1',
      reason: 'ReDoS vulnerability (CVE-2020-26237)',
      remediation: 'Update to highlight.js@10.4.1 or later.'
    },
    'moment': {
      severity: 'medium',
      versions: '<2.29.4',
      reason: 'Path traversal vulnerability (CVE-2022-31129)',
      remediation: 'Update to moment@2.29.4 or consider using day.js.'
    },
    'shell-quote': {
      severity: 'critical',
      versions: '<1.7.3',
      reason: 'Command injection (CVE-2021-42740)',
      remediation: 'Update to shell-quote@1.7.3 or later.'
    },
    'simple-git': {
      severity: 'critical',
      versions: '<3.15.0',
      reason: 'Remote code execution (CVE-2022-25912)',
      remediation: 'Update to simple-git@3.15.0 or later.'
    },
    'cross-fetch': {
      severity: 'medium',
      versions: '<3.1.5',
      reason: 'Exposure of sensitive information',
      remediation: 'Update to cross-fetch@3.1.5 or later.'
    },
    'nanoid': {
      severity: 'medium',
      versions: '<3.1.31',
      reason: 'Predictable output vulnerability',
      remediation: 'Update to nanoid@3.1.31 or later.'
    },
    'immer': {
      severity: 'high',
      versions: '<9.0.6',
      reason: 'Prototype pollution (CVE-2021-23436)',
      remediation: 'Update to immer@9.0.6 or later.'
    },
  };

  /**
   * Packages with security concerns (not necessarily vulnerable)
   */
  static SECURITY_CONCERNS = {
    'eval': { reason: 'Allows arbitrary code execution', severity: 'critical' },
    'serialize-javascript': { reason: 'Can lead to XSS if misused', severity: 'medium' },
    'crypto': { reason: 'Node.js crypto is OK, but ensure not using deprecated methods', severity: 'info' },
    'request': { reason: 'Deprecated, use node-fetch or axios instead', severity: 'low' },
    'querystring': { reason: 'Deprecated, use URLSearchParams instead', severity: 'low' },
    'node-uuid': { reason: 'Deprecated, use uuid package instead', severity: 'low' },
    'mkdirp': { reason: 'Consider using fs.mkdir with recursive: true', severity: 'info' },
  };

  /**
   * Run all dependency security checks
   */
  async analyze() {
    console.error('[Dependencies] Analyzing dependency security...');

    await Promise.all([
      this.analyzePackageJson(),
      this.analyzePackageLock(),
      this.analyzePythonDeps(),
      this.checkLockfileExists(),
    ]);

    return {
      findings: this.findings,
      summary: this.generateSummary()
    };
  }

  addFinding(finding) {
    this.findings.push({
      category: 'dependency-security',
      ...finding
    });
  }

  /**
   * Analyze package.json dependencies
   */
  async analyzePackageJson() {
    try {
      const content = await readFile(join(this.projectPath, 'package.json'), 'utf-8');
      const pkg = JSON.parse(content);

      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
        ...pkg.peerDependencies,
        ...pkg.optionalDependencies
      };

      // Check for known vulnerabilities
      for (const [name, version] of Object.entries(allDeps)) {
        const vuln = DependencySecurityAnalyzer.KNOWN_VULNERABILITIES[name];

        if (vuln) {
          // Check if version is affected (simplified check)
          const isAffected = this.isVersionAffected(version, vuln.versions);

          if (isAffected || !vuln.versions) {
            this.addFinding({
              severity: vuln.severity,
              title: `Vulnerable Package: ${name}`,
              description: vuln.reason,
              remediation: vuln.remediation,
              location: {
                file: 'package.json',
                package: name,
                version: version,
                affectedVersions: vuln.versions || 'all'
              }
            });
          }
        }

        // Check for security concerns
        const concern = DependencySecurityAnalyzer.SECURITY_CONCERNS[name];
        if (concern) {
          this.addFinding({
            severity: concern.severity,
            title: `Security Concern: ${name}`,
            description: concern.reason,
            remediation: `Consider alternatives or review usage of ${name}.`,
            location: { file: 'package.json', package: name }
          });
        }
      }

      // Check for git dependencies (supply chain risk)
      for (const [name, version] of Object.entries(allDeps)) {
        if (version.includes('git://') || version.includes('github:')) {
          this.addFinding({
            severity: 'medium',
            title: `Git Dependency: ${name}`,
            description: 'Package installed from git - not verified through npm registry.',
            remediation: 'Prefer published npm packages. Pin to specific commit if necessary.',
            location: { file: 'package.json', package: name }
          });
        }

        // Check for HTTP URLs (should be HTTPS)
        if (version.includes('http://')) {
          this.addFinding({
            severity: 'high',
            title: `Insecure HTTP Dependency: ${name}`,
            description: 'Package URL uses HTTP instead of HTTPS.',
            remediation: 'Change to HTTPS URL or use npm registry.',
            location: { file: 'package.json', package: name }
          });
        }
      }

      // Check for missing security scripts
      const scripts = pkg.scripts || {};
      if (!scripts.audit && !scripts['security:check']) {
        this.addFinding({
          severity: 'info',
          title: 'No Security Audit Script',
          description: 'No npm audit script in package.json.',
          remediation: 'Add "audit": "npm audit" to scripts for regular checks.',
          location: { file: 'package.json' }
        });
      }

      // Check for preinstall/postinstall scripts (supply chain)
      if (scripts.preinstall || scripts.postinstall) {
        this.addFinding({
          severity: 'info',
          title: 'Install Scripts Present',
          description: 'Package has preinstall/postinstall scripts. Verify they are trusted.',
          remediation: 'Review scripts to ensure no malicious commands.',
          location: { file: 'package.json' }
        });
      }

      // Check for version ranges (supply chain risk)
      const riskyVersions = [];
      for (const [name, version] of Object.entries(pkg.dependencies || {})) {
        if (version.startsWith('^') || version.startsWith('~') || version === '*' || version === 'latest') {
          riskyVersions.push(name);
        }
      }

      if (riskyVersions.length > 10) {
        this.addFinding({
          severity: 'low',
          title: 'Many Packages Use Version Ranges',
          description: `${riskyVersions.length} packages use ^, ~, or * versions.`,
          remediation: 'Consider pinning critical dependencies for reproducible builds.',
          location: { file: 'package.json' }
        });
      }

    } catch {
      // No package.json
    }
  }

  /**
   * Analyze package-lock.json for deeper issues
   */
  async analyzePackageLock() {
    try {
      const content = await readFile(join(this.projectPath, 'package-lock.json'), 'utf-8');
      const lock = JSON.parse(content);

      // Check lockfile version
      if (lock.lockfileVersion < 2) {
        this.addFinding({
          severity: 'low',
          title: 'Old Lockfile Version',
          description: `package-lock.json uses version ${lock.lockfileVersion}.`,
          remediation: 'Run npm i to update to lockfileVersion 3.',
          location: { file: 'package-lock.json' }
        });
      }

      // Analyze all resolved dependencies
      const packages = lock.packages || {};
      const dependencies = lock.dependencies || {};

      // Check for known vulnerabilities in transitive deps
      const depsToCheck = { ...packages, ...this.flattenDeps(dependencies) };

      for (const [path, info] of Object.entries(depsToCheck)) {
        const name = path.replace('node_modules/', '').split('node_modules/').pop();
        const version = info.version;

        if (!name || !version) continue;

        const vuln = DependencySecurityAnalyzer.KNOWN_VULNERABILITIES[name];
        if (vuln && this.isVersionAffected(version, vuln.versions)) {
          this.addFinding({
            severity: vuln.severity,
            title: `Vulnerable Transitive Dependency: ${name}`,
            description: `${vuln.reason} (version ${version})`,
            remediation: `${vuln.remediation} Run 'npm audit fix' or manually update.`,
            location: {
              file: 'package-lock.json',
              package: name,
              version: version,
              path: path
            }
          });
        }
      }

    } catch {
      // No package-lock.json
    }
  }

  /**
   * Check if lockfile exists
   */
  async checkLockfileExists() {
    const lockfiles = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'];
    let hasLockfile = false;

    for (const lockfile of lockfiles) {
      try {
        await access(join(this.projectPath, lockfile));
        hasLockfile = true;
        break;
      } catch {
        // File doesn't exist
      }
    }

    if (!hasLockfile) {
      try {
        // Only warn if package.json exists
        await access(join(this.projectPath, 'package.json'));
        this.addFinding({
          severity: 'high',
          title: 'Missing Lockfile',
          description: 'No package-lock.json, yarn.lock, or pnpm-lock.yaml found.',
          remediation: 'Run npm install to generate package-lock.json. Commit it to git.',
          location: { file: 'package.json' }
        });
      } catch {
        // No package.json either, not a Node project
      }
    }
  }

  /**
   * Analyze Python dependencies
   */
  async analyzePythonDeps() {
    const pythonVulns = {
      'django': { versions: '<3.2.14', reason: 'SQL injection vulnerability' },
      'flask': { versions: '<2.0.0', reason: 'Various security fixes' },
      'requests': { versions: '<2.27.0', reason: 'Cookie leakage vulnerability' },
      'pillow': { versions: '<9.0.0', reason: 'Multiple buffer overflow vulnerabilities' },
      'pyyaml': { versions: '<5.4', reason: 'Arbitrary code execution vulnerability' },
      'urllib3': { versions: '<1.26.5', reason: 'ReDoS vulnerability' },
      'jinja2': { versions: '<2.11.3', reason: 'XSS vulnerability in error pages' },
      'paramiko': { versions: '<2.10.1', reason: 'Authentication bypass vulnerability' },
      'cryptography': { versions: '<36.0.0', reason: 'Various security improvements' },
      'lxml': { versions: '<4.6.5', reason: 'XXE vulnerability' },
    };

    const reqFiles = ['requirements.txt', 'requirements-dev.txt', 'Pipfile'];

    for (const reqFile of reqFiles) {
      try {
        const content = await readFile(join(this.projectPath, reqFile), 'utf-8');

        for (const [pkg, vuln] of Object.entries(pythonVulns)) {
          const regex = new RegExp(`^${pkg}[=<>~!]+(\\d[^\\s]*)`, 'mi');
          const match = content.match(regex);

          if (match) {
            this.addFinding({
              severity: 'high',
              title: `Potentially Vulnerable Python Package: ${pkg}`,
              description: `${vuln.reason}. Current version: ${match[1]}`,
              remediation: `Update ${pkg} to latest version: pip install --upgrade ${pkg}`,
              location: { file: reqFile, package: pkg }
            });
          }
        }

        // Check for unpinned versions
        const unpinnedCount = (content.match(/^[a-zA-Z][a-zA-Z0-9_-]*\s*$/gm) || []).length;
        if (unpinnedCount > 5) {
          this.addFinding({
            severity: 'medium',
            title: 'Many Unpinned Python Dependencies',
            description: `${unpinnedCount} packages without version pins.`,
            remediation: 'Pin versions: pip freeze > requirements.txt',
            location: { file: reqFile }
          });
        }

      } catch {
        // File doesn't exist
      }
    }
  }

  /**
   * Check if version is affected by vulnerability
   */
  isVersionAffected(version, affectedVersions) {
    if (!affectedVersions) return true;

    // Clean version string
    version = version.replace(/^[\^~>=<]/, '').split(' ')[0];

    // Parse affected versions (simplified)
    if (affectedVersions.startsWith('<')) {
      const maxVersion = affectedVersions.replace('<', '');
      return this.compareVersions(version, maxVersion) < 0;
    }

    return false;
  }

  /**
   * Simple semantic version comparison
   */
  compareVersions(a, b) {
    const pa = a.split('.').map(x => parseInt(x) || 0);
    const pb = b.split('.').map(x => parseInt(x) || 0);

    for (let i = 0; i < 3; i++) {
      const na = pa[i] || 0;
      const nb = pb[i] || 0;
      if (na > nb) return 1;
      if (na < nb) return -1;
    }
    return 0;
  }

  /**
   * Flatten nested dependencies from old lockfile format
   */
  flattenDeps(deps, result = {}) {
    for (const [name, info] of Object.entries(deps)) {
      result[`node_modules/${name}`] = { version: info.version };
      if (info.dependencies) {
        this.flattenDeps(info.dependencies, result);
      }
    }
    return result;
  }

  /**
   * Generate summary
   */
  generateSummary() {
    const bySeverity = {
      critical: 0, high: 0, medium: 0, low: 0, info: 0
    };

    for (const finding of this.findings) {
      bySeverity[finding.severity]++;
    }

    return {
      total: this.findings.length,
      bySeverity,
      recommendation: this.getTopRecommendation(bySeverity)
    };
  }

  getTopRecommendation(bySeverity) {
    if (bySeverity.critical > 0) {
      return 'Critical vulnerabilities found. Run npm audit fix --force immediately.';
    }
    if (bySeverity.high > 0) {
      return 'High severity issues found. Run npm audit and update affected packages.';
    }
    if (bySeverity.medium > 0) {
      return 'Medium severity issues found. Schedule updates for affected packages.';
    }
    return 'No critical dependency issues found.';
  }
}

export default DependencySecurityAnalyzer;
