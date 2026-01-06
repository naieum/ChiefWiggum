# Parallel Security Scan

Dispatch multiple security scans simultaneously for faster audits.

## When to Use This Skill

Use this skill when:
- Running a full security audit and want faster results
- Scanning a large codebase
- Time is limited but thorough scanning is needed
- Different scan types have no dependencies on each other

## Parallelization Strategy

### Independent Scan Groups

These scans can run in parallel because they examine different aspects:

```
Group A (Dependencies & Secrets):
├── scan_dependencies      # Checks package.json, lock files
├── check_live_cves        # Queries OSV database
└── audit_env_files        # Checks .env files

Group B (Code Analysis):
├── scan_project_security  # Static analysis for injections, XSS
└── check_react_vulns      # React-specific patterns

Group C (Infrastructure):
├── scan_framework_security  # Framework-specific checks
├── scan_database_security   # Database configuration
└── scan_api_security        # API endpoint security

Group D (Auth & Config):
├── scan_auth_security     # Authentication patterns
└── audit_config           # Configuration files
```

### Execution Plan

```
Timeline (parallel execution):
─────────────────────────────────────────────────────────►
│
│  ┌─────────────────┐
│  │ Group A         │ (fastest - dependency checks)
│  │ ~30 seconds     │
│  └─────────────────┘
│
│  ┌───────────────────────┐
│  │ Group B               │ (static analysis)
│  │ ~1-2 minutes          │
│  └───────────────────────┘
│
│  ┌─────────────────────────────┐
│  │ Group C                     │ (infrastructure)
│  │ ~1-2 minutes                │
│  └─────────────────────────────┘
│
│  ┌───────────────────┐
│  │ Group D           │ (auth & config)
│  │ ~1 minute         │
│  └───────────────────┘
│
Total: ~2 minutes (vs ~6 minutes sequential)
```

## Dispatching Subagents

Using Superpowers' parallel agent dispatch:

### Agent 1: Dependency Scanner
```markdown
## Task: Dependency Security Scan

Run the following Guardian-Agent tools and compile results:
1. `scan_dependencies` - Check for known vulnerable packages
2. `check_live_cves` - Query OSV for latest vulnerabilities
3. `check_react_vulnerabilities` - If React project, check ecosystem

Return: JSON with all findings, grouped by severity
```

### Agent 2: Code Analyzer
```markdown
## Task: Static Code Analysis

Run the following Guardian-Agent tools:
1. `scan_project_security` with scan_type='full'
2. Check for hardcoded secrets
3. Check for injection vulnerabilities

Return: JSON with all findings, file locations, and suggested fixes
```

### Agent 3: Infrastructure Auditor
```markdown
## Task: Infrastructure Security Audit

Run the following Guardian-Agent tools:
1. `scan_framework_security` - Framework-specific issues
2. `scan_database_security` - Database configuration
3. `scan_api_security` - API security

Return: JSON with findings and configuration recommendations
```

### Agent 4: Auth & Config Reviewer
```markdown
## Task: Auth and Configuration Review

Run the following Guardian-Agent tools:
1. `scan_auth_security` - Authentication patterns
2. `audit_env_files` - Environment variable security
3. `check_gitignore` - Sensitive file exposure

Return: JSON with findings and security recommendations
```

## Merging Results

After all agents complete, merge findings:

```javascript
function mergeSecurityResults(agentResults) {
  const allFindings = [];
  const seen = new Set();

  for (const result of agentResults) {
    for (const finding of result.findings) {
      // Deduplicate by unique key
      const key = `${finding.title}:${finding.location?.file}:${finding.location?.line}`;
      if (!seen.has(key)) {
        seen.add(key);
        allFindings.push(finding);
      }
    }
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  allFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return allFindings;
}
```

## Coordination Pattern

```
┌─────────────────────────────────────────────────────────┐
│                    Coordinator Agent                     │
├─────────────────────────────────────────────────────────┤
│  1. Detect tech stack (sequential - needed for routing) │
│  2. Dispatch parallel agents based on detected stack    │
│  3. Wait for all agents to complete                     │
│  4. Merge and deduplicate results                       │
│  5. Generate unified report                             │
│  6. Calculate security score                            │
└─────────────────────────────────────────────────────────┘
         │           │           │           │
         ▼           ▼           ▼           ▼
    ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐
    │Agent 1 │  │Agent 2 │  │Agent 3 │  │Agent 4 │
    │  Deps  │  │  Code  │  │ Infra  │  │  Auth  │
    └────────┘  └────────┘  └────────┘  └────────┘
```

## Error Handling

If an agent fails:
1. Log the failure with context
2. Continue with other agents
3. Mark that scan area as incomplete
4. Include partial results in final report
5. Recommend manual review for failed areas

```javascript
async function runParallelScans(agents) {
  const results = await Promise.allSettled(agents.map(a => a.run()));

  const successful = [];
  const failed = [];

  for (const [i, result] of results.entries()) {
    if (result.status === 'fulfilled') {
      successful.push(result.value);
    } else {
      failed.push({
        agent: agents[i].name,
        error: result.reason.message
      });
    }
  }

  return { successful, failed };
}
```

## Usage with Claude Code

When using Guardian-Agent in Claude Code:

```
User: Run a full security scan

Claude: I'll run a parallel security scan for faster results.

[Dispatches 4 agents simultaneously]

Agent 1 (Dependencies): Found 3 vulnerable packages
Agent 2 (Code): Found 2 SQL injection risks
Agent 3 (Infrastructure): Found 1 RLS policy issue
Agent 4 (Auth): Found 1 JWT configuration issue

Total: 7 findings in 2 minutes (vs 6 minutes sequential)
```
