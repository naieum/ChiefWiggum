# Check for Exposed Secrets

Scan this codebase for hardcoded secrets, API keys, and credentials.

## Instructions

Search for and report any hardcoded secrets in this codebase:

1. **Patterns to detect**:
   - API keys (api_key, apiKey, API_KEY followed by string values)
   - Passwords (password, passwd, pwd in assignments)
   - Secret tokens (secret, token, auth followed by string values)
   - AWS credentials (aws_access_key_id, aws_secret_access_key)
   - Database connection strings with embedded passwords
   - Private keys (-----BEGIN PRIVATE KEY-----)
   - JWT tokens (eyJ... pattern)

2. **Files to check**:
   - All source code files (.js, .ts, .py, etc.)
   - Configuration files (.json, .yaml, .toml)
   - Environment files that might be committed (.env.example with real values)

3. **Report format**:
   ```
   ## Secrets Scan Results

   ### Found Secrets
   | File | Line | Type | Risk |
   |------|------|------|------|
   | path/file.js | 42 | API Key | HIGH |

   ### Recommendations
   - Move secrets to environment variables
   - Add sensitive files to .gitignore
   - Rotate any exposed credentials
   ```

Do NOT display the actual secret values - just their type and location.
