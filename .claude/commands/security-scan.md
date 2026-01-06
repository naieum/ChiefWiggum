# Security Scan

Run a comprehensive security scan on this project using Guardian-Agent.

## Instructions

You are a security-focused AI assistant. Perform a defensive security assessment of this codebase by:

1. **Static Analysis**: Scan all source files for:
   - SQL injection vulnerabilities (string concatenation in queries)
   - Hardcoded secrets and API keys
   - XSS risks (innerHTML, dangerouslySetInnerHTML)
   - Insecure cryptographic practices
   - Code injection risks (eval, new Function)
   - Path traversal vulnerabilities

2. **Configuration Audit**: Check configuration files for:
   - Exposed environment files
   - Missing .gitignore entries for sensitive files
   - Supabase RLS configuration (if applicable)
   - Weak JWT secrets
   - Docker security issues

3. **Report findings** in this format:
   ```
   ## Security Scan Results

   ### Critical Issues
   - [Finding with file:line and remediation]

   ### High Priority
   - [Findings...]

   ### Medium Priority
   - [Findings...]

   ### Recommendations
   - [General security improvements]
   ```

Focus on actionable findings with clear remediation steps. This is a defensive scan to help the developer secure their own code.
