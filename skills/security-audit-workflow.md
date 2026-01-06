# Security Audit Workflow

A structured security audit workflow following the Superpowers methodology.

## When to Use This Skill

Use this skill when:
- Starting a comprehensive security review of a project
- Onboarding to a new codebase and need to assess security posture
- Preparing for a security-focused release
- After a security incident to identify other vulnerabilities

## The Seven Phases

### Phase 1: Discovery
Before scanning, understand the project:

1. **Detect the tech stack** - Run `detect_tech_stack` to identify all technologies
2. **Map the attack surface** - Identify entry points (APIs, forms, auth flows)
3. **Identify sensitive data** - Find where secrets, PII, and tokens are handled
4. **Review architecture** - Understand data flow and trust boundaries

```
Questions to answer:
- What frameworks and databases are used?
- Where does user input enter the system?
- What authentication/authorization is in place?
- Where are secrets stored and how are they accessed?
```

### Phase 2: Environment Setup
Prepare for the audit:

1. **Create a security branch** - Use git worktree for isolation
2. **Set up reporting** - Choose output format (markdown, SARIF, JSON)
3. **Define scope** - What's in/out of scope for this audit
4. **Establish baseline** - Document current security state

```bash
git worktree add ../security-audit-$(date +%Y%m%d) -b security/audit-$(date +%Y%m%d)
```

### Phase 3: Planning
Break the audit into focused chunks:

1. **Dependency scan** - 5 min - Check for vulnerable packages
2. **Secret scan** - 5 min - Find hardcoded credentials
3. **Injection scan** - 10 min - SQL, NoSQL, command injection
4. **Auth audit** - 10 min - Authentication and session security
5. **API audit** - 10 min - Rate limiting, validation, CORS
6. **Framework audit** - 10 min - Framework-specific issues
7. **Config audit** - 5 min - Security misconfigurations

Each chunk should be completable in under 15 minutes.

### Phase 4: Execution
Run scans systematically:

```
For each scan chunk:
1. Run the appropriate Guardian-Agent tool
2. Document findings immediately
3. Categorize by severity (critical/high/medium/low)
4. Note false positives for later review
5. Move to next chunk
```

**Parallel execution**: Use `dispatching-parallel-agents` to run independent scans simultaneously:
- Dependencies + Secrets (no overlap)
- Framework + Database (stack-specific)
- Auth + API (related but separable)

### Phase 5: Analysis
Review and prioritize findings:

1. **Deduplicate** - Remove duplicate findings
2. **Verify** - Confirm true positives, mark false positives
3. **Prioritize** - Rank by exploitability and impact
4. **Group** - Cluster related issues for efficient fixing

```
Priority Matrix:
┌─────────────┬──────────────┬──────────────┐
│             │ Easy to Fix  │ Hard to Fix  │
├─────────────┼──────────────┼──────────────┤
│ High Impact │ FIX NOW      │ PLAN FIX     │
├─────────────┼──────────────┼──────────────┤
│ Low Impact  │ QUICK WIN    │ BACKLOG      │
└─────────────┴──────────────┴──────────────┘
```

### Phase 6: Remediation
Fix issues using TDD approach:

1. **Write failing test** - Prove the vulnerability exists
2. **Implement fix** - Apply the security patch
3. **Verify test passes** - Confirm the fix works
4. **Regression test** - Ensure nothing broke

Use the `security-fix-tdd` skill for each fix.

### Phase 7: Completion
Finalize the audit:

1. **Generate report** - Use `generate_security_report`
2. **Calculate score** - Use `security_score` for grade
3. **Document exceptions** - Note accepted risks
4. **Create tickets** - For deferred fixes
5. **Merge or PR** - Get fixes into main branch

## Output Artifacts

After completing this workflow, you should have:

- [ ] Security score (A-F grade)
- [ ] Findings report (markdown or SARIF)
- [ ] Fixed vulnerabilities (with tests)
- [ ] Backlog of deferred issues
- [ ] Updated .gitignore and .env.example

## Integration with Superpowers

This skill integrates with:
- `writing-plans` - For planning the audit
- `executing-plans` - For systematic execution
- `dispatching-parallel-agents` - For concurrent scanning
- `test-driven-development` - For security fixes
- `requesting-code-review` - For fix validation
