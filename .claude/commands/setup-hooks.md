# Setup Security Hooks

Generate and install a pre-commit hook to prevent committing security issues.

Use the Guardian-Agent `generate_pre_commit_hook` tool to:
1. Create a hook that checks for hardcoded secrets
2. Block .env files from being committed
3. Warn about debug code (console.log, debugger)

Then use `install_pre_commit_hook` to install it, or provide manual installation instructions.
