# Using Guardian-Agent

Introduction to Guardian-Agent security scanner and its integration with Superpowers.

## What is Guardian-Agent?

Guardian-Agent is a defensive security scanner plugin for Claude Code that helps developers find and fix vulnerabilities in their own projects. It's designed for "vibe coders" who want to keep their websites safe without being security experts.

## Core Principles

1. **Self-assessment only** - Scans your own code, never external targets
2. **Stack-aware** - Detects your tech stack and runs relevant checks
3. **Actionable** - Provides fixes, not just findings
4. **Up-to-date** - Queries live CVE databases for latest vulnerabilities

## Available Tools

### Discovery Tools

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `detect_tech_stack` | Identify all technologies | Start of any audit |
| `security_score` | Get A-F security grade | Quick health check |

### Scanning Tools

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `run_full_scan` | Comprehensive scan | Full security audit |
| `scan_project_security` | Code vulnerabilities | After code changes |
| `scan_dependencies` | Package vulnerabilities | After npm install |
| `check_live_cves` | Latest CVE data | Regular checks |
| `check_react_vulnerabilities` | React ecosystem | React projects |

### Specialized Scans

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `scan_framework_security` | Framework-specific | Next.js, Express, etc. |
| `scan_database_security` | Database config | Supabase, MongoDB, etc. |
| `scan_auth_security` | Auth implementation | After auth changes |
| `scan_api_security` | API endpoints | After API changes |

### Environment Tools

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `audit_env_files` | Check .env security | Before commits |
| `check_localhost_headers` | HTTP headers | Development server |
| `pre_commit_hook` | Generate git hooks | Project setup |

### Remediation Tools

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `generate_security_fix` | Auto-generate patches | After finding issues |
| `generate_security_report` | Create reports | End of audit |

## Quick Start

### 1. Check Your Security Score

```
/security-scan

This will:
1. Detect your tech stack
2. Run appropriate scans
3. Give you an A-F grade
4. List top issues to fix
```

### 2. Fix Critical Issues First

```
Focus on:
1. Hardcoded secrets → Move to .env
2. SQL injection → Use parameterized queries
3. Missing auth → Add authentication checks
4. Exposed admin routes → Add authorization
```

### 3. Set Up Prevention

```
/check-secrets

This will generate a pre-commit hook to prevent
committing secrets in the future.
```

## Integration with Superpowers

Guardian-Agent works seamlessly with Superpowers skills:

### With `security-audit-workflow`
Follow a structured 7-phase security audit process.

### With `security-fix-tdd`
Fix vulnerabilities using test-driven development.

### With `parallel-security-scan`
Run multiple scans simultaneously for faster audits.

### With `vulnerability-remediation`
Systematic workflow for fixing and verifying fixes.

## Slash Commands

| Command | Description |
|---------|-------------|
| `/security-scan` | Run full security scan |
| `/check-secrets` | Scan for hardcoded secrets |
| `/check-react` | Check React vulnerabilities |
| `/audit-supabase` | Audit Supabase configuration |

## Best Practices

### Daily Development
- Run `/check-secrets` before commits
- Check dependencies after `npm install`

### Weekly
- Run `security_score` to track progress
- Review any new CVEs with `check_live_cves`

### Before Releases
- Run `run_full_scan`
- Fix all critical and high issues
- Generate security report

### After Incidents
- Full audit with `security-audit-workflow`
- Document findings
- Implement fixes with TDD

## Understanding Severity Levels

```
CRITICAL - Immediate exploitation possible
           Examples: RCE, auth bypass, exposed secrets
           Action: Fix immediately, consider incident response

HIGH     - Significant risk, exploitation likely
           Examples: SQL injection, stored XSS
           Action: Fix within 24 hours

MEDIUM   - Moderate risk, may need specific conditions
           Examples: CSRF, reflected XSS, weak crypto
           Action: Fix within 1 week

LOW      - Minor risk, limited impact
           Examples: Info disclosure, missing headers
           Action: Fix in next sprint

INFO     - Best practice recommendations
           Examples: Deprecated APIs, optimization
           Action: Consider when convenient
```

## Getting Help

- Use `/help` for Claude Code help
- Check the skills folder for detailed workflows
- Report issues at the project repository
