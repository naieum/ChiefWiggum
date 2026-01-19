# Check OAuth Security

Scan OAuth and social login implementations for security issues.

Use the Guardian-Agent `scan_oauth_security` tool to check:

## Supported Providers
- NextAuth.js / Auth.js
- Clerk
- Supabase Auth
- Firebase Auth
- Auth0
- Passport.js

## What It Checks
1. **State parameter** - CSRF protection in OAuth flow
2. **PKCE** - Required for SPAs and mobile apps
3. **Token storage** - localStorage vs httpOnly cookies
4. **Redirect validation** - Open redirect vulnerabilities
5. **Secret exposure** - Client secrets in browser code
6. **Provider configuration** - Provider-specific misconfigurations

## Common Issues Found
- Missing NEXTAUTH_SECRET
- getSession() instead of getUser() on server
- Tokens stored in localStorage
- Unvalidated redirect URLs
- OAuth secrets in source code

Explain any findings and how to fix them.
