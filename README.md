# Guardian-Agent

**A security testing plugin for Claude that won't let you shoot yourself in the foot.**

Guardian is a vulnerability assessment tool designed to work with Claude. The twist? It's built around the idea that security testing should be hard to screw up. You have to explicitly authorize everything, it prioritizes tests that don't break things, and it keeps a log of everything you do.

---

## What Is This Thing?

Guardian follows a four-phase security testing workflow:

1. **Reconnaissance** - Figure out what tech the target is using
2. **Discovery** - Find API endpoints and entry points
3. **Targeted Testing** - Run security checks based on what was found
4. **Reporting** - Generate a report with findings and fixes

The key thing: it won't do anything dangerous unless you explicitly tell it to.

---

## Project Structure (What's Where)

```
guardian_agent/
├── plugin.py              # The main orchestrator - ties everything together
├── authorization.py       # Makes sure you have permission before doing anything
│
├── phases/
│   ├── reconnaissance.py  # Detects Supabase, MongoDB, Next.js, etc.
│   ├── discovery.py       # Finds /api/, /admin/, /auth/ endpoints
│   ├── targeted_testing.py # The actual security tests
│   └── reporting.py       # Generates the final report
│
├── checks/
│   ├── supabase_checks.py # RLS policies, key exposure
│   ├── mongodb_checks.py  # NoSQL injection patterns
│   ├── react_checks.py    # XSS, Server Actions, RSC issues
│   └── api_checks.py      # BOLA, IDOR, rate limiting
│
├── utils/
│   ├── safe_checks.py     # Non-destructive tests (won't break anything)
│   └── rate_limiter.py    # Prevents hammering the target
│
└── schemas/
    └── report_schema.py   # JSON schema for reports
```

---

## What Each File Does

### The Core

**`plugin.py`** - This is the brain. The `GuardianAgent` class coordinates all four phases. It talks to Claude through tool definitions (`guardian_authorize`, `guardian_assess`, etc.) and makes sure authorization is checked before every operation.

**`authorization.py`** - The gatekeeper. Nothing happens without going through here. Tracks:
- What domains/IPs you're allowed to test
- What's explicitly excluded (like production)
- Whether you have permission for "active" tests (the ones that might break stuff)
- An audit log of every authorization decision

### The Phases

**`phases/reconnaissance.py`** - Passive fingerprinting. Looks at response headers, error messages, and JavaScript patterns to detect:
- Databases: Supabase, MongoDB, PostgreSQL, MySQL, Firebase, Redis, DynamoDB
- Frameworks: Next.js, React, Express, Django, FastAPI, Remix, etc.
- Auth providers: Auth0, Okta, Supabase Auth, Firebase Auth

**`phases/discovery.py`** - Endpoint mapping. Brute-forces common paths like `/api/v1/`, `/admin/`, `/graphql/`, `/swagger/`. Respects rate limiting.

**`phases/targeted_testing.py`** - The decision tree. Based on what reconnaissance found, it picks the right tests:
- Found Supabase? Check RLS policies, anonymous access, key exposure
- Found MongoDB? Check for NoSQL operator injection
- Found Next.js? Check Server Actions, RSC serialization, __NEXT_DATA__ leaks

**`phases/reporting.py`** - Generates reports with CVSS scores, impact analysis, remediation steps, and CWE/OWASP references.

### The Checks

**`checks/supabase_checks.py`** - Supabase-specific tests:
- RLS (Row Level Security) misconfiguration
- Service role key exposed in client code
- Storage bucket permissions
- Anonymous key overpermissions

**`checks/mongodb_checks.py`** - NoSQL injection patterns:
- Operator injection (`$ne`, `$gt`, `$exists`)
- Auth bypass via query manipulation
- ObjectId enumeration

**`checks/react_checks.py`** - React/Next.js vulnerabilities:
- XSS via `dangerouslySetInnerHTML`
- `javascript:` protocol in hrefs
- Prototype pollution
- Server Action injection
- RSC serialization attacks
- Source map exposure

**`checks/api_checks.py`** - Generic API tests:
- BOLA/IDOR (accessing other users' stuff)
- Rate limiting
- Mass assignment
- SSRF

### The Utilities

**`utils/safe_checks.py`** - The "I promise not to break anything" tests. These only read data, never write. They're the default and don't need special approval.

**`utils/rate_limiter.py`** - Token bucket rate limiter with adaptive backoff. Prevents you from accidentally DoS-ing the target.

---

## The Two Types of Tests

### Safe Checks (Default)

These run without special permission:
- Checking headers for technology indicators
- Looking for exposed API keys in JavaScript
- Analyzing JWT token structure
- Testing for error-based SQL injection (just triggers errors, doesn't extract data)
- Checking for missing security headers

### Active Tests (Require Explicit Approval)

These need `exploit_approval=True`:
- Authentication bypass attempts
- SQL injection data extraction
- Parameter tampering
- SSRF exploitation

You also need to provide an `authorization_document` reference (proof you have permission).

---

## What Could Go Wrong

### 1. Running Against Unauthorized Targets

The authorization system tries to prevent this, but it's not magic. If you authorize a domain, it'll test that domain. Make sure you actually have permission.

**Risk**: Legal trouble. Unauthorized security testing is illegal in most places.

### 2. Active Tests Breaking Things

The active tests (the ones requiring `exploit_approval`) can modify application state. That's why they're gated behind an explicit flag.

**Risk**: You could:
- Lock out accounts during auth bypass testing
- Trigger rate limiting or IP bans
- Corrupt data during injection testing

**Mitigation**: Run against staging/test environments. Have a rollback plan.

### 3. Rate Limiting Issues

Even with the built-in rate limiter, rapid requests can trigger target defenses or cause performance issues.

**Risk**: Getting blocked, skewing results, or degrading target performance.

### 4. False Positives/Negatives

Guardian uses pattern matching and heuristics. It might:
- Flag things as vulnerable when they're not
- Miss vulnerabilities it doesn't have patterns for
- Misidentify the tech stack

**Mitigation**: Verify findings manually before reporting.

### 5. Key Detection Has Limits

The service role key detection looks for patterns in JavaScript. If someone obfuscates their code or uses unusual patterns, it might miss exposed keys.

### 6. Reconnaissance Accuracy

Tech fingerprinting is based on headers and patterns. Modern deployments with proxies, CDNs, or custom configurations might be misidentified.

### 7. Scope Creep

If you authorize `*.example.com`, you're authorizing all subdomains. Be careful with wildcards.

---

## Should You Send This to a Claude Agent for Review?

**Yes, I'd recommend running this through Claude in plan mode.** Here's why:

### What's Good

1. **Authorization-first design** - You literally can't skip the permission step
2. **Safe checks are the default** - Active testing requires explicit opt-in
3. **Audit logging** - Everything gets recorded
4. **Technology-aware testing** - Tests are selected based on actual stack, not generic scanning
5. **Rate limiting built-in** - Won't accidentally hammer targets

### What Could Use Review

1. **The HTTP callback pattern** - The actual HTTP requests are delegated to a callback. Need to verify this is implemented safely in the Claude integration.

2. **Scope validation** - The `is_target_authorized` check is substring-based. A Claude review could verify this doesn't have edge cases (like `evil-example.com` matching `example.com`).

3. **Test coverage gaps** - The test cases cover common vulnerabilities but might miss:
   - GraphQL-specific issues
   - WebSocket security
   - OAuth flow vulnerabilities
   - Newer framework-specific issues

4. **Error handling** - Some of the check implementations have placeholder logic (comments like "Note: In real implementation, make HTTP request"). A review should verify these are complete.

5. **React/Next.js checks** - These are pattern-based and might need updating as the frameworks evolve. Server Components security is a moving target.

### Suggested Plan Mode Questions

When running this through Claude, ask:

1. "Review the authorization flow - are there any bypass scenarios?"
2. "Check the scope validation logic for edge cases"
3. "Are there any modern vulnerabilities missing from the test cases?"
4. "Review the safe_checks.py implementations - are they actually non-destructive?"
5. "Check the rate limiter for race conditions"

---

## Quick Start

```python
from guardian_agent import GuardianAgent, AuthorizationScope, AuthorizationLevel
from datetime import datetime, timedelta

agent = GuardianAgent()

# Define what you're allowed to test
scope = AuthorizationScope(
    target_domains=["api.staging.example.com"],
    exclusions=["api.production.example.com"],
    authorization_document="PENTEST-2024-001",
    authorized_by="security@example.com",
    expiration_date=datetime.now() + timedelta(days=7)
)

# Authorize (default: safe checks only)
success, msg = agent.authorize(scope, level=AuthorizationLevel.SAFE_CHECK)

# Run the assessment
success, report = agent.run_full_assessment("https://api.staging.example.com")

# Get results
print(agent.export_report())
```

---

## The Philosophy

Guardian takes the position that security testing tools should be:

1. **Hard to misuse** - Authorization is mandatory, not optional
2. **Safe by default** - Destructive tests require explicit approval
3. **Auditable** - Every decision gets logged
4. **Stack-aware** - Generic scanning is noisy; targeted testing is useful

The name "Guardian" is intentional - it's meant to guard against both attackers AND testers accidentally breaking things.

---

## License

MIT. Use responsibly. Get authorization before testing anything you don't own.

---

*Built for Claude integration. Test safely.*
