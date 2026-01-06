# Check Environment Files

Audit all .env files in this project for security issues.

Use the Guardian-Agent `audit_env_files` tool to:
1. Find all .env files in the project
2. Check if they're properly gitignored
3. Scan for exposed secrets and API keys
4. Verify .env.example exists

If issues are found, explain how to fix them.
