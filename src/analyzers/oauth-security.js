/**
 * OAuth Security Analyzer
 *
 * Checks for common OAuth/OIDC vulnerabilities:
 * - Missing state parameter (CSRF)
 * - Open redirect vulnerabilities
 * - Token storage issues
 * - PKCE not implemented
 * - Insecure token handling
 * - Provider-specific misconfigurations
 */

import { readFile, readdir } from 'fs/promises';
import { join, extname } from 'path';

export class OAuthSecurityAnalyzer {
  constructor(projectPath, detectedStack = {}) {
    this.projectPath = projectPath;
    this.detectedStack = detectedStack;
    this.findings = [];
  }

  /**
   * Run all OAuth security checks
   */
  async analyze() {
    console.error('[OAuth] Analyzing OAuth security...');

    const analyzedProviders = [];

    // Detect OAuth providers in use
    const providers = await this.detectOAuthProviders();
    console.error(`[OAuth] Detected providers: ${providers.join(', ') || 'none'}`);

    // Run checks based on detected providers
    if (providers.includes('nextauth')) {
      await this.checkNextAuth();
      analyzedProviders.push('NextAuth.js');
    }

    if (providers.includes('clerk')) {
      await this.checkClerk();
      analyzedProviders.push('Clerk');
    }

    if (providers.includes('supabase-auth')) {
      await this.checkSupabaseAuth();
      analyzedProviders.push('Supabase Auth');
    }

    if (providers.includes('firebase-auth')) {
      await this.checkFirebaseAuth();
      analyzedProviders.push('Firebase Auth');
    }

    if (providers.includes('auth0')) {
      await this.checkAuth0();
      analyzedProviders.push('Auth0');
    }

    if (providers.includes('passport')) {
      await this.checkPassport();
      analyzedProviders.push('Passport.js');
    }

    // Generic OAuth pattern checks (always run)
    await this.checkGenericOAuthPatterns();
    await this.checkTokenStorage();
    await this.checkRedirectValidation();
    await this.checkStateParameter();
    await this.checkPKCE();
    await this.checkTokenLeakage();
    await this.checkSocialLoginConfig();

    return {
      findings: this.findings,
      analyzedProviders,
      summary: this.generateSummary()
    };
  }

  /**
   * Detect which OAuth providers are in use
   */
  async detectOAuthProviders() {
    const providers = [];

    try {
      const packageJson = await readFile(join(this.projectPath, 'package.json'), 'utf-8');
      const pkg = JSON.parse(packageJson);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };

      if (deps['next-auth'] || deps['@auth/core']) providers.push('nextauth');
      if (deps['@clerk/nextjs'] || deps['@clerk/clerk-react']) providers.push('clerk');
      if (deps['@supabase/supabase-js'] || deps['@supabase/auth-helpers-nextjs']) providers.push('supabase-auth');
      if (deps['firebase'] || deps['firebase-admin']) providers.push('firebase-auth');
      if (deps['@auth0/nextjs-auth0'] || deps['auth0-js']) providers.push('auth0');
      if (deps['passport'] || deps['passport-oauth2']) providers.push('passport');
      if (deps['oauth'] || deps['simple-oauth2']) providers.push('generic-oauth');

    } catch {
      // No package.json
    }

    return providers;
  }

  /**
   * Check NextAuth.js configuration
   */
  async checkNextAuth() {
    console.error('[OAuth] Checking NextAuth.js configuration...');

    const sourceFiles = await this.getSourceFiles();

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for NextAuth config
        if (!content.includes('NextAuth') && !content.includes('next-auth')) continue;

        // Check for missing NEXTAUTH_SECRET
        if (content.includes('NextAuth') && !content.includes('secret')) {
          // Check if it's the main config file
          if (relativePath.includes('auth') || relativePath.includes('api')) {
            this.findings.push({
              severity: 'critical',
              title: 'NextAuth missing secret configuration',
              description: `${relativePath} - NextAuth requires a secret for production. Without it, JWTs can be forged.`,
              category: 'oauth-config',
              location: { file: relativePath },
              remediation: 'Add NEXTAUTH_SECRET environment variable and configure secret in NextAuth options.'
            });
          }
        }

        // Check for debug mode in production
        if (/debug:\s*true/.test(content)) {
          this.findings.push({
            severity: 'medium',
            title: 'NextAuth debug mode enabled',
            description: `${relativePath} - Debug mode exposes sensitive information. Disable in production.`,
            category: 'oauth-config',
            location: { file: relativePath },
            remediation: 'Set debug: false or use debug: process.env.NODE_ENV === "development"'
          });
        }

        // Check for missing callbacks validation
        if (content.includes('callbacks') && content.includes('redirect')) {
          if (!/baseUrl|startsWith|origin/.test(content)) {
            this.findings.push({
              severity: 'high',
              title: 'NextAuth redirect callback may allow open redirect',
              description: `${relativePath} - The redirect callback should validate the destination URL.`,
              category: 'oauth-redirect',
              location: { file: relativePath },
              remediation: 'Validate redirect URL starts with your domain: if (url.startsWith(baseUrl)) return url;'
            });
          }
        }

        // Check for JWT callback without proper checks
        if (content.includes('jwt') && content.includes('callback')) {
          if (content.includes('token') && !content.includes('token.exp')) {
            this.findings.push({
              severity: 'medium',
              title: 'NextAuth JWT callback may not check token expiry',
              description: `${relativePath} - JWT callbacks should validate token expiration.`,
              category: 'oauth-token',
              location: { file: relativePath },
              remediation: 'Check token.exp in JWT callback to handle expired tokens properly.'
            });
          }
        }

        // Check for session callback exposing sensitive data
        if (/session.*callback[\s\S]*?user\./.test(content)) {
          if (/user\.(password|secret|token|apiKey)/i.test(content)) {
            this.findings.push({
              severity: 'high',
              title: 'NextAuth session may expose sensitive user data',
              description: `${relativePath} - Session callback appears to expose sensitive user properties.`,
              category: 'oauth-token',
              location: { file: relativePath },
              remediation: 'Only include necessary user data in session. Never expose passwords or tokens.'
            });
          }
        }

      } catch {
        // Skip unreadable files
      }
    }
  }

  /**
   * Check Clerk configuration
   */
  async checkClerk() {
    console.error('[OAuth] Checking Clerk configuration...');

    const sourceFiles = await this.getSourceFiles();

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for Clerk publishable key in code
        if (/pk_(?:live|test)_[A-Za-z0-9]+/.test(content)) {
          // Publishable key is OK in client code
        }

        // Check for Clerk secret key exposure
        if (/sk_(?:live|test)_[A-Za-z0-9]+/.test(content)) {
          this.findings.push({
            severity: 'critical',
            title: 'Clerk secret key hardcoded',
            description: `${relativePath} - Clerk secret key found in source code.`,
            category: 'oauth-secrets',
            location: { file: relativePath },
            remediation: 'Move to CLERK_SECRET_KEY environment variable. Never commit secret keys.'
          });
        }

        // Check for missing auth middleware
        if (relativePath.includes('middleware') && content.includes('clerk')) {
          if (!content.includes('authMiddleware') && !content.includes('clerkMiddleware')) {
            this.findings.push({
              severity: 'medium',
              title: 'Clerk middleware may not be properly configured',
              description: `${relativePath} - Ensure Clerk auth middleware is protecting routes.`,
              category: 'oauth-config',
              location: { file: relativePath },
              remediation: 'Use authMiddleware or clerkMiddleware to protect routes.'
            });
          }
        }

      } catch {
        // Skip unreadable files
      }
    }
  }

  /**
   * Check Supabase Auth configuration
   */
  async checkSupabaseAuth() {
    console.error('[OAuth] Checking Supabase Auth configuration...');

    const sourceFiles = await this.getSourceFiles();

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        if (!content.includes('supabase')) continue;

        // Check for getSession without getUser validation
        if (content.includes('getSession') && !content.includes('getUser')) {
          if (relativePath.includes('api') || relativePath.includes('server')) {
            this.findings.push({
              severity: 'high',
              title: 'Supabase using getSession() on server without getUser()',
              description: `${relativePath} - getSession() is not secure for server-side auth checks. Session can be spoofed.`,
              category: 'oauth-token',
              location: { file: relativePath },
              remediation: 'Use getUser() for server-side authentication. getSession() only validates JWT format, not authenticity.'
            });
          }
        }

        // Check for service role key in client code
        if (content.includes('service_role') || /supabaseServiceRole|SUPABASE_SERVICE/.test(content)) {
          if (!relativePath.includes('server') && !relativePath.includes('api')) {
            this.findings.push({
              severity: 'critical',
              title: 'Supabase service role key may be exposed to client',
              description: `${relativePath} - Service role key bypasses RLS. Never expose to client.`,
              category: 'oauth-secrets',
              location: { file: relativePath },
              remediation: 'Only use service role key in server-side code (API routes, server actions).'
            });
          }
        }

        // Check for signInWithOAuth without redirect validation
        if (content.includes('signInWithOAuth')) {
          if (content.includes('redirectTo') && !/origin|localhost|process\.env/.test(content)) {
            this.findings.push({
              severity: 'medium',
              title: 'Supabase OAuth redirectTo may be vulnerable',
              description: `${relativePath} - Ensure redirectTo URL is validated against allowed origins.`,
              category: 'oauth-redirect',
              location: { file: relativePath },
              remediation: 'Use redirectTo: `${window.location.origin}/auth/callback` or similar.'
            });
          }
        }

        // Check email confirmation settings
        if (content.includes('signUp') && !content.includes('emailConfirm')) {
          this.findings.push({
            severity: 'low',
            title: 'Supabase email confirmation not explicitly checked',
            description: `${relativePath} - Consider requiring email confirmation before granting access.`,
            category: 'oauth-config',
            location: { file: relativePath },
            remediation: 'Check email_confirmed_at in user metadata or enable "Confirm email" in Supabase dashboard.'
          });
        }

      } catch {
        // Skip unreadable files
      }
    }
  }

  /**
   * Check Firebase Auth configuration
   */
  async checkFirebaseAuth() {
    console.error('[OAuth] Checking Firebase Auth configuration...');

    const sourceFiles = await this.getSourceFiles();

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        if (!content.includes('firebase')) continue;

        // Check for client-side admin SDK usage
        if (content.includes('firebase-admin') || content.includes('admin.auth')) {
          if (!relativePath.includes('server') && !relativePath.includes('api') && !relativePath.includes('functions')) {
            this.findings.push({
              severity: 'critical',
              title: 'Firebase Admin SDK may be exposed to client',
              description: `${relativePath} - Admin SDK has full database access. Never use in client code.`,
              category: 'oauth-secrets',
              location: { file: relativePath },
              remediation: 'Only use firebase-admin in server-side code (API routes, Cloud Functions).'
            });
          }
        }

        // Check for onAuthStateChanged without proper handling
        if (content.includes('onAuthStateChanged')) {
          if (!content.includes('unsubscribe') && !content.includes('return')) {
            this.findings.push({
              severity: 'low',
              title: 'Firebase auth listener may not be cleaned up',
              description: `${relativePath} - onAuthStateChanged should return unsubscribe function.`,
              category: 'oauth-config',
              location: { file: relativePath },
              remediation: 'Store and call the unsubscribe function when component unmounts.'
            });
          }
        }

        // Check for ID token verification on server
        if (relativePath.includes('api') || relativePath.includes('server')) {
          if (content.includes('currentUser') && !content.includes('verifyIdToken')) {
            this.findings.push({
              severity: 'high',
              title: 'Firebase server code may not verify ID tokens',
              description: `${relativePath} - Server-side code should verify ID tokens, not trust client state.`,
              category: 'oauth-token',
              location: { file: relativePath },
              remediation: 'Use admin.auth().verifyIdToken(idToken) to verify tokens server-side.'
            });
          }
        }

      } catch {
        // Skip unreadable files
      }
    }
  }

  /**
   * Check Auth0 configuration
   */
  async checkAuth0() {
    console.error('[OAuth] Checking Auth0 configuration...');

    const sourceFiles = await this.getSourceFiles();

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        if (!content.includes('auth0')) continue;

        // Check for hardcoded client secret
        if (/clientSecret:\s*['"][^'"]+['"]/.test(content)) {
          this.findings.push({
            severity: 'critical',
            title: 'Auth0 client secret hardcoded',
            description: `${relativePath} - Auth0 client secret found in source code.`,
            category: 'oauth-secrets',
            location: { file: relativePath },
            remediation: 'Move to AUTH0_CLIENT_SECRET environment variable.'
          });
        }

        // Check for audience configuration
        if (content.includes('getAccessToken') && !content.includes('audience')) {
          this.findings.push({
            severity: 'medium',
            title: 'Auth0 access token may not have audience set',
            description: `${relativePath} - Without audience, token may be opaque and not validatable.`,
            category: 'oauth-config',
            location: { file: relativePath },
            remediation: 'Configure audience in Auth0 to receive JWT access tokens.'
          });
        }

      } catch {
        // Skip unreadable files
      }
    }
  }

  /**
   * Check Passport.js configuration
   */
  async checkPassport() {
    console.error('[OAuth] Checking Passport.js configuration...');

    const sourceFiles = await this.getSourceFiles();

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        if (!content.includes('passport')) continue;

        // Check for missing state in OAuth strategies
        if (content.includes('OAuth2Strategy') || content.includes('GoogleStrategy')) {
          if (!content.includes('state:') && !content.includes('state=')) {
            this.findings.push({
              severity: 'high',
              title: 'Passport OAuth strategy missing state parameter',
              description: `${relativePath} - OAuth without state parameter is vulnerable to CSRF.`,
              category: 'oauth-csrf',
              location: { file: relativePath },
              remediation: 'Enable state: true in strategy options or use passReqToCallback with custom state.'
            });
          }
        }

        // Check for failureRedirect to sensitive info
        if (/failureRedirect.*error|failed|denied/i.test(content)) {
          this.findings.push({
            severity: 'low',
            title: 'Passport failure redirect may leak information',
            description: `${relativePath} - Failure redirect path may indicate authentication failure to attackers.`,
            category: 'oauth-config',
            location: { file: relativePath },
            remediation: 'Use generic redirect like /login?error=1 instead of descriptive paths.'
          });
        }

        // Check for session serialization issues
        if (content.includes('serializeUser') && content.includes('deserializeUser')) {
          if (/serialize.*user\)/.test(content) && !/user\.(id|_id)/.test(content)) {
            this.findings.push({
              severity: 'medium',
              title: 'Passport may serialize entire user object',
              description: `${relativePath} - Serializing full user object stores sensitive data in session.`,
              category: 'oauth-token',
              location: { file: relativePath },
              remediation: 'Only serialize user.id: done(null, user.id)'
            });
          }
        }

      } catch {
        // Skip unreadable files
      }
    }
  }

  /**
   * Check generic OAuth patterns
   */
  async checkGenericOAuthPatterns() {
    console.error('[OAuth] Checking generic OAuth patterns...');

    const sourceFiles = await this.getSourceFiles();

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for OAuth client secrets in code
        const secretPatterns = [
          /client[_-]?secret\s*[:=]\s*['"][A-Za-z0-9_-]{20,}['"]/i,
          /oauth[_-]?secret\s*[:=]\s*['"][^'"]+['"]/i,
        ];

        for (const pattern of secretPatterns) {
          if (pattern.test(content)) {
            this.findings.push({
              severity: 'critical',
              title: 'OAuth client secret hardcoded in source',
              description: `${relativePath} - OAuth client secrets should never be in source code.`,
              category: 'oauth-secrets',
              location: { file: relativePath },
              remediation: 'Move to environment variables (e.g., OAUTH_CLIENT_SECRET).'
            });
            break;
          }
        }

        // Check for OAuth token in URL
        if (/[?&](access_token|token|code)=/.test(content) && /window\.location|href/.test(content)) {
          this.findings.push({
            severity: 'high',
            title: 'OAuth token may be exposed in URL',
            description: `${relativePath} - Tokens in URLs can leak via referrer headers and browser history.`,
            category: 'oauth-token',
            location: { file: relativePath },
            remediation: 'Use POST for token exchange. Remove tokens from URL immediately after reading.'
          });
        }

      } catch {
        // Skip unreadable files
      }
    }
  }

  /**
   * Check token storage practices
   */
  async checkTokenStorage() {
    console.error('[OAuth] Checking token storage practices...');

    const sourceFiles = await this.getSourceFiles();

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for localStorage token storage
        if (/localStorage\.(setItem|getItem).*token/i.test(content)) {
          this.findings.push({
            severity: 'high',
            title: 'OAuth tokens stored in localStorage',
            description: `${relativePath} - localStorage is vulnerable to XSS. Tokens can be stolen by malicious scripts.`,
            category: 'oauth-storage',
            location: { file: relativePath },
            remediation: 'Use httpOnly cookies for token storage, or in-memory with refresh token rotation.'
          });
        }

        // Check for sessionStorage (slightly better but still vulnerable)
        if (/sessionStorage\.(setItem|getItem).*token/i.test(content)) {
          this.findings.push({
            severity: 'medium',
            title: 'OAuth tokens stored in sessionStorage',
            description: `${relativePath} - sessionStorage is vulnerable to XSS in the same tab.`,
            category: 'oauth-storage',
            location: { file: relativePath },
            remediation: 'Prefer httpOnly cookies. sessionStorage is acceptable for low-sensitivity tokens only.'
          });
        }

        // Check for token in cookie without httpOnly
        if (/document\.cookie.*token/i.test(content)) {
          this.findings.push({
            severity: 'high',
            title: 'Token set via document.cookie (not httpOnly)',
            description: `${relativePath} - Cookies set via JavaScript are not httpOnly and vulnerable to XSS.`,
            category: 'oauth-storage',
            location: { file: relativePath },
            remediation: 'Set tokens via server response with httpOnly, Secure, and SameSite flags.'
          });
        }

      } catch {
        // Skip unreadable files
      }
    }
  }

  /**
   * Check redirect URL validation
   */
  async checkRedirectValidation() {
    console.error('[OAuth] Checking redirect URL validation...');

    const sourceFiles = await this.getSourceFiles();

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for unvalidated redirects
        if (/redirect[_-]?uri\s*[=:]/i.test(content) || /callback[_-]?url/i.test(content)) {
          // Check if there's validation
          if (!/allowedDomains|validRedirect|whitelist|startsWith.*origin/i.test(content)) {
            // Check if redirect comes from user input
            if (/req\.(query|body|params).*redirect/i.test(content) ||
                /searchParams.*redirect/i.test(content)) {
              this.findings.push({
                severity: 'high',
                title: 'Potential open redirect in OAuth flow',
                description: `${relativePath} - Redirect URL from user input without validation.`,
                category: 'oauth-redirect',
                location: { file: relativePath },
                remediation: 'Validate redirect URLs against an allowlist of trusted domains.'
              });
            }
          }
        }

        // Check for redirect without origin validation
        if (/res\.redirect\s*\(\s*req\.(query|body)/.test(content)) {
          this.findings.push({
            severity: 'high',
            title: 'Redirect from user input without validation',
            description: `${relativePath} - Redirecting to user-provided URL enables open redirect attacks.`,
            category: 'oauth-redirect',
            location: { file: relativePath },
            remediation: 'Validate: const url = new URL(redirect, origin); if (url.origin === origin) redirect(url);'
          });
        }

      } catch {
        // Skip unreadable files
      }
    }
  }

  /**
   * Check state parameter usage
   */
  async checkStateParameter() {
    console.error('[OAuth] Checking state parameter usage...');

    const sourceFiles = await this.getSourceFiles();

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check if file is OAuth related
        if (!/oauth|authorize|callback|signin/i.test(content)) continue;

        // Check for authorization URL construction without state
        if (/authorize\?|authorization_endpoint|\/auth\?/i.test(content)) {
          if (!content.includes('state=') && !content.includes('state:')) {
            this.findings.push({
              severity: 'high',
              title: 'OAuth authorization without state parameter',
              description: `${relativePath} - Missing state parameter makes OAuth vulnerable to CSRF attacks.`,
              category: 'oauth-csrf',
              location: { file: relativePath },
              remediation: 'Generate random state, store in session, verify on callback: state=crypto.randomUUID()'
            });
          }
        }

        // Check if state is validated on callback
        if (/callback|redirect_uri/i.test(relativePath) || /code.*exchange|token.*endpoint/i.test(content)) {
          if (content.includes('state') && !/state.*===|state.*!==|verifyState|checkState/i.test(content)) {
            this.findings.push({
              severity: 'high',
              title: 'OAuth state parameter may not be validated',
              description: `${relativePath} - State parameter must be verified against stored value.`,
              category: 'oauth-csrf',
              location: { file: relativePath },
              remediation: 'Compare received state with session-stored state: if (state !== storedState) throw Error;'
            });
          }
        }

      } catch {
        // Skip unreadable files
      }
    }
  }

  /**
   * Check PKCE implementation
   */
  async checkPKCE() {
    console.error('[OAuth] Checking PKCE implementation...');

    const sourceFiles = await this.getSourceFiles();
    let hasPublicClient = false;
    let hasPKCE = false;

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');

        // Detect if this is a public client (SPA, mobile)
        if (/react|vue|angular|next|nuxt|expo|react-native/i.test(content)) {
          hasPublicClient = true;
        }

        // Check for PKCE implementation
        if (/code_verifier|code_challenge|pkce/i.test(content)) {
          hasPKCE = true;
        }

      } catch {
        // Skip unreadable files
      }
    }

    // Check package.json for SPA indicators
    try {
      const packageJson = await readFile(join(this.projectPath, 'package.json'), 'utf-8');
      if (/react|vue|angular|next|nuxt|svelte/i.test(packageJson)) {
        hasPublicClient = true;
      }
    } catch {
      // No package.json
    }

    if (hasPublicClient && !hasPKCE) {
      this.findings.push({
        severity: 'medium',
        title: 'PKCE not detected for public client',
        description: 'Public clients (SPAs, mobile apps) should use PKCE for OAuth authorization code flow.',
        category: 'oauth-pkce',
        location: { file: 'Project-wide' },
        remediation: `Implement PKCE:
1. Generate code_verifier: crypto.randomBytes(32).toString('base64url')
2. Create code_challenge: base64url(sha256(code_verifier))
3. Send code_challenge with authorize request
4. Send code_verifier with token exchange`
      });
    }
  }

  /**
   * Check for token leakage
   */
  async checkTokenLeakage() {
    console.error('[OAuth] Checking for token leakage...');

    const sourceFiles = await this.getSourceFiles();

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for tokens in console.log
        if (/console\.(log|debug|info).*token/i.test(content)) {
          this.findings.push({
            severity: 'high',
            title: 'OAuth token may be logged to console',
            description: `${relativePath} - Logging tokens exposes them in browser console and server logs.`,
            category: 'oauth-leakage',
            location: { file: relativePath },
            remediation: 'Remove token logging. Use token: "***" for debugging if needed.'
          });
        }

        // Check for tokens in error messages
        if (/throw.*Error.*token|reject.*token/i.test(content)) {
          this.findings.push({
            severity: 'medium',
            title: 'OAuth token may be exposed in error messages',
            description: `${relativePath} - Error messages with tokens can leak to users or logs.`,
            category: 'oauth-leakage',
            location: { file: relativePath },
            remediation: 'Never include tokens in error messages.'
          });
        }

        // Check for token in fetch/axios URL (should be header)
        if (/fetch\s*\([^)]*token=/i.test(content) || /axios.*url.*token=/i.test(content)) {
          this.findings.push({
            severity: 'high',
            title: 'OAuth token passed in URL instead of header',
            description: `${relativePath} - Tokens in URLs leak via server logs, browser history, and referrer headers.`,
            category: 'oauth-leakage',
            location: { file: relativePath },
            remediation: 'Pass tokens in Authorization header: { headers: { Authorization: `Bearer ${token}` } }'
          });
        }

      } catch {
        // Skip unreadable files
      }
    }
  }

  /**
   * Check social login configuration
   */
  async checkSocialLoginConfig() {
    console.error('[OAuth] Checking social login configuration...');

    // Check for environment variables
    try {
      const envFiles = ['.env', '.env.local', '.env.example'];

      for (const envFile of envFiles) {
        try {
          const content = await readFile(join(this.projectPath, envFile), 'utf-8');

          // Check for social provider configs
          const providers = ['GOOGLE', 'GITHUB', 'FACEBOOK', 'TWITTER', 'DISCORD', 'APPLE', 'LINKEDIN'];

          for (const provider of providers) {
            // Check for client secret in example file
            if (envFile.includes('example')) {
              if (new RegExp(`${provider}.*SECRET.*[A-Za-z0-9]{10,}`, 'i').test(content)) {
                this.findings.push({
                  severity: 'high',
                  title: `${provider} OAuth secret in .env.example`,
                  description: `.env.example contains real-looking ${provider} secret. This file is committed.`,
                  category: 'oauth-secrets',
                  location: { file: envFile },
                  remediation: 'Use placeholder values in .env.example: GOOGLE_CLIENT_SECRET=your-secret-here'
                });
              }
            }

            // Check for missing scopes documentation
            if (new RegExp(`${provider}.*ID`, 'i').test(content) && !new RegExp(`${provider}.*SCOPE`, 'i').test(content)) {
              this.findings.push({
                severity: 'info',
                title: `${provider} OAuth scopes not configured`,
                description: `${provider} OAuth configured but scopes not explicitly set. Default scopes may be overly permissive.`,
                category: 'oauth-config',
                location: { file: envFile },
                remediation: 'Explicitly configure scopes to request minimum necessary permissions.'
              });
            }
          }

        } catch {
          // File doesn't exist
        }
      }

    } catch {
      // No env files
    }
  }

  /**
   * Get source files
   */
  async getSourceFiles() {
    const extensions = ['.js', '.jsx', '.ts', '.tsx', '.mjs'];
    const files = [];

    const walk = async (dir) => {
      try {
        const entries = await readdir(dir, { withFileTypes: true });

        for (const entry of entries) {
          const fullPath = join(dir, entry.name);

          if (entry.isDirectory()) {
            // Skip common non-source directories
            if (['node_modules', '.git', 'dist', 'build', '.next', '.nuxt', 'coverage'].includes(entry.name)) {
              continue;
            }
            await walk(fullPath);
          } else if (extensions.includes(extname(entry.name))) {
            files.push(fullPath);
          }
        }
      } catch {
        // Skip unreadable directories
      }
    };

    await walk(this.projectPath);
    return files.slice(0, 500); // Limit for performance
  }

  /**
   * Generate summary
   */
  generateSummary() {
    const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

    for (const f of this.findings) {
      summary[f.severity]++;
    }

    const categoryCount = {};
    for (const f of this.findings) {
      categoryCount[f.category] = (categoryCount[f.category] || 0) + 1;
    }

    return {
      bySeverity: summary,
      byCategory: categoryCount,
      total: this.findings.length,
      topIssues: Object.entries(categoryCount)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([cat, count]) => `${cat}: ${count}`)
    };
  }
}

export default OAuthSecurityAnalyzer;
