# Guardian-Agent

A **defensive security scanner** plugin for Claude Code that helps developers find and fix vulnerabilities in their own projects.

## What This Is

Guardian-Agent is a security self-assessment tool designed for developers who "vibe code" and want to keep their websites safe. It scans YOUR OWN codebase for common security issues and provides actionable remediation guidance.

**This is NOT a penetration testing tool.** It's a defensive scanner that:
- Reads your source code to find vulnerability patterns
- Audits your configuration files for security issues
- Checks your localhost server for missing security headers
- Generates reports with remediation steps

## Features

### Static Analysis
Scans your code for:
- SQL injection vulnerabilities
- Hardcoded secrets and API keys
- XSS risks (innerHTML, dangerouslySetInnerHTML)
- NoSQL injection patterns
- Insecure cryptographic practices
- Code execution risks (eval, exec)
- Path traversal vulnerabilities

### Configuration Audit
Checks your config files for:
- Environment file security
- Supabase RLS configuration
- JWT secret strength
- Docker security issues
- Missing .gitignore entries

### Safe Dynamic Checks
Tests your localhost server for:
- Missing security headers (HSTS, CSP, etc.)
- CORS misconfigurations
- Cookie security flags
- Information disclosure

## Installation

### Option 1: Claude Code MCP Plugin (Recommended)

Install Guardian-Agent as an MCP server in Claude Code:

```bash
# Clone the repo
git clone https://github.com/naieum/ChiefWiggum.git
cd ChiefWiggum

# Copy the MCP config to your project
cp .mcp.json /path/to/your/project/.mcp.json

# Or install globally for all projects
cp .mcp.json ~/.claude/.mcp.json
```

Then in Claude Code, you can use:
- `@security-auditor scan my project` - Run a full security scan
- `@security-auditor check database config` - Audit database settings
- `@security-auditor check localhost headers` - Test your dev server

### Option 2: Standalone Installation

```bash
# Clone the repo
git clone https://github.com/naieum/ChiefWiggum.git

# Navigate to the directory
cd ChiefWiggum

# No dependencies required - uses Node.js built-ins
```

## Usage

### As an MCP Plugin in Claude Code

Once installed, the following tools are available:

| Tool | Description |
|------|-------------|
| `scan_project_security` | Scan source files for vulnerabilities |
| `audit_database_config` | Check Supabase/Postgres/MongoDB config |
| `check_localhost_headers` | Test HTTP security headers on localhost |
| `generate_security_report` | Generate JSON/Markdown/SARIF reports |

Example conversation:
```
You: Scan this project for security issues
Claude: [Uses scan_project_security tool]
       Found 3 issues: 1 critical, 2 medium...
```

### As a Node.js Module

```javascript
import GuardianAgent from './src/index.js';

const agent = new GuardianAgent('/path/to/your/project');

// Run full scan
const results = await agent.runFullScan();
console.log(JSON.stringify(results.report, null, 2));

// Or run individual scans
const staticResults = await agent.runStaticOnly();
const configResults = await agent.runConfigAuditOnly();
```

### Claude Code Slash Commands

Copy the `.claude/commands/` directory to your project to get these commands:

- `/security-scan` - Run a comprehensive security scan
- `/check-secrets` - Scan for hardcoded secrets
- `/audit-supabase` - Audit Supabase configuration

## Report Format

Reports follow a consistent JSON schema:

```json
{
  "metadata": {
    "generatedAt": "2024-01-15T10:30:00Z",
    "tool": "Guardian-Agent"
  },
  "summary": {
    "totalFindings": 5,
    "bySeverity": {
      "critical": 1,
      "high": 2,
      "medium": 2,
      "low": 0,
      "info": 0
    },
    "riskScore": 45,
    "riskLevel": "MEDIUM"
  },
  "findings": [
    {
      "id": "GUARD-0001",
      "severity": "critical",
      "title": "Hardcoded API Key",
      "description": "API key found in source code",
      "impact": "Exposed credentials could allow unauthorized access",
      "remediation": "Move to environment variables",
      "location": {
        "file": "src/api.js",
        "line": 42
      }
    }
  ]
}
```

## Security Philosophy

Guardian-Agent follows these principles:

1. **Self-assessment only** - Designed to scan your own projects
2. **Non-destructive** - Read-only operations, no data modification
3. **Localhost only** - Dynamic checks restricted to localhost
4. **Education-focused** - Explains WHY something is a vulnerability
5. **Actionable** - Provides specific remediation steps

## What This Doesn't Do

- Attack or exploit vulnerabilities
- Test systems you don't own
- Brute-force directories or credentials
- Generate attack payloads
- Bypass security controls

## Contributing

Contributions welcome! Please focus on:
- Adding detection patterns for new vulnerability types
- Improving remediation guidance
- Supporting additional frameworks/languages
- Better reporting formats

## License

MIT License - See [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for self-assessment of your own projects. Always get proper authorization before testing any system. The authors are not responsible for misuse.
