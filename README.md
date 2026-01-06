# Guardian-Agent

A Claude Plugin for **Authorized** Vulnerability Assessment & Penetration Testing (VAPT).

> ⚠️ **IMPORTANT**: This tool is designed for authorized security testing only. Always obtain proper written authorization before testing any system.

## Overview

Guardian-Agent is a security assessment plugin that follows a strict VAPT lifecycle with built-in safeguards and authorization controls. It prioritizes non-destructive "Safe-Checks" and requires explicit "Exploit-Approval" before any active testing.

## Features

- **Authorization-First Approach**: No testing without explicit approval and defined scope
- **Safe-Check Priority**: Non-destructive checks run first
- **Technology-Aware Testing**: Tests tailored to detected stack (Supabase, MongoDB, PostgreSQL, etc.)
- **Exploit-Approval Flag**: Active testing requires explicit consent
- **Comprehensive Reporting**: Findings with severity, CVSS scores, impact analysis, and remediation

## VAPT Lifecycle Phases

### Phase 1: Reconnaissance

Fingerprinting tools for detecting target technology stack:

- **Databases**: Supabase, MongoDB, PostgreSQL, MySQL, Redis, Firebase, DynamoDB
- **Frameworks**: Express, Django, FastAPI, Rails, Spring, Next.js
- **Cloud Services**: AWS, GCP, Azure, Vercel
- **Authentication**: Auth0, Okta, Firebase Auth, Supabase Auth

```python
from guardian_agent import GuardianAgent

agent = GuardianAgent()
success, fingerprint = agent.run_reconnaissance_only("https://api.example.com")
print(f"Detected databases: {fingerprint.databases}")
print(f"Detected frameworks: {fingerprint.frameworks}")
```

### Phase 2: Discovery

Directory brute-forcing and API endpoint mapping:

- Common API paths (`/api/v1`, `/graphql`, `/rest`)
- Authentication endpoints (`/auth`, `/login`, `/oauth`)
- Admin interfaces (`/admin`, `/dashboard`, `/console`)
- Debug endpoints (`/debug`, `/actuator`, `/metrics`)
- Documentation (`/swagger`, `/docs`, `/openapi.json`)

### Phase 3: Targeted Testing

Decision tree for vulnerability testing based on detected stack:

| Detected Tech | Priority Tests (Safe Checks) | Requires Exploit-Approval |
|---------------|------------------------------|---------------------------|
| **Supabase**  | RLS Policy, Anonymous Access, Key Exposure | Auth Bypass, SQL Injection via RPC |
| **MongoDB**   | Operator Injection, Auth Bypass Indicators | JS Injection, Data Exfiltration |
| **PostgreSQL**| Error-based SQLi Detection | UNION-based, Blind SQLi |
| **Generic API**| BOLA/IDOR, Rate Limiting, Data Exposure | Mass Assignment, SSRF |

### Phase 4: Reporting

JSON schema-compliant reports with:

- **Executive Summary**: High-level risk assessment
- **Findings**: Detailed vulnerability documentation
- **CVSS Scores**: Industry-standard severity ratings
- **Impact Analysis**: Business and technical impact
- **Remediation Steps**: Actionable fix guidance
- **References**: CWE IDs, OWASP categories

## Quick Start

```python
from guardian_agent import GuardianAgent, AuthorizationScope, AuthorizationLevel
from datetime import datetime, timedelta

# Initialize the agent
agent = GuardianAgent()

# Step 1: Define authorization scope
scope = AuthorizationScope(
    target_domains=["api.example.com", "*.example.com"],
    target_ips=["192.168.1.0/24"],
    exclusions=["production.example.com"],  # Explicitly excluded
    authorization_document="PENTEST-2024-001",
    authorized_by="security@example.com",
    expiration_date=datetime.now() + timedelta(days=7)
)

# Step 2: Set authorization level
# - SAFE_CHECK: Non-destructive tests only
# - EXPLOIT_APPROVAL: Full testing (requires exploit_approval=True)
success, msg = agent.authorize(
    scope=scope,
    level=AuthorizationLevel.SAFE_CHECK,
    exploit_approval=False
)

# Step 3: Run assessment
success, report = agent.run_full_assessment("https://api.example.com")

# Step 4: Export report
print(agent.export_report(format=ReportFormat.JSON))
```

## Authorization Controls

### Authorization Levels

1. **NONE**: No active testing, only passive information gathering
2. **SAFE_CHECK**: Non-destructive checks only (default)
3. **EXPLOIT_APPROVAL**: Full testing including active exploitation

### Exploit-Approval Requirements

To enable active testing:

```python
agent.authorize(
    scope=scope,
    level=AuthorizationLevel.EXPLOIT_APPROVAL,
    exploit_approval=True  # Must be explicitly True
)
```

Requirements for EXPLOIT_APPROVAL:
- `authorization_document` must be specified in scope
- `exploit_approval` flag must be explicitly `True`
- Written authorization should exist referencing the document ID

## Safe Checks vs Active Tests

### Safe Checks (No Approval Required)

- Analyze response headers for technology indicators
- Check for exposed API keys in client code
- Test for information disclosure in error messages
- Verify security header configuration
- Detect NoSQL injection via read-only operators
- Analyze JWT token structure

### Active Tests (Require Exploit-Approval)

- Authentication bypass attempts
- SQL injection data extraction
- Parameter tampering
- Mass assignment testing
- SSRF exploitation

## Report Schema

Reports follow a JSON schema with the following structure:

```json
{
  "metadata": {
    "report_id": "GAR-20241215-A1B2C3",
    "title": "Security Assessment Report",
    "generated_at": "2024-12-15T10:30:00Z"
  },
  "target": "https://api.example.com",
  "scope": {
    "authorized_targets": ["api.example.com"],
    "exclusions": ["production.example.com"]
  },
  "findings": {
    "total": 5,
    "by_severity": {
      "critical": 1,
      "high": 2,
      "medium": 1,
      "low": 1
    },
    "items": [
      {
        "id": "F-SUP-001-143052",
        "title": "Supabase RLS Policy Misconfiguration",
        "severity": "critical",
        "cvss_score": 9.1,
        "description": "...",
        "impact": "...",
        "remediation": {
          "description": "Enable RLS policies...",
          "effort": "medium"
        },
        "cwe_ids": ["CWE-284"],
        "owasp_category": "A01:2021 – Broken Access Control"
      }
    ]
  }
}
```

## Project Structure

```
guardian_agent/
├── __init__.py           # Package entry point
├── plugin.py             # Main GuardianAgent orchestrator
├── authorization.py      # Authorization management
├── phases/
│   ├── reconnaissance.py # Phase 1: Tech fingerprinting
│   ├── discovery.py      # Phase 2: Endpoint mapping
│   ├── targeted_testing.py # Phase 3: Vulnerability testing
│   └── reporting.py      # Phase 4: Report generation
├── checks/
│   ├── supabase_checks.py # Supabase-specific tests
│   ├── mongodb_checks.py  # MongoDB-specific tests
│   └── api_checks.py      # Generic API tests
├── schemas/
│   └── report_schema.py   # JSON schema definitions
└── utils/
    ├── rate_limiter.py    # Request rate limiting
    └── safe_checks.py     # Safe check implementations
```

## Ethical Guidelines

1. **Always Obtain Authorization**: Never test systems without explicit written permission
2. **Define Scope Clearly**: Know exactly what you're allowed to test
3. **Document Everything**: Keep audit logs of all testing activities
4. **Report Responsibly**: Follow responsible disclosure practices
5. **Minimize Impact**: Use rate limiting and avoid destructive tests unless necessary

## License

This project is for authorized security testing purposes only.

---

**Guardian-Agent** - Security Testing with Authorization First
