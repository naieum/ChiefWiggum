/**
 * Authentication & Session Security Analyzer
 *
 * Deep security checks for authentication implementations:
 * - JWT handling and security
 * - Session management
 * - Password storage
 * - OAuth/OIDC configuration
 * - Auth provider configurations
 */

import { readFile, readdir } from 'fs/promises';
import { join, extname } from 'path';

export class AuthSecurityAnalyzer {
  constructor(projectPath, detectedStack) {
    this.projectPath = projectPath;
    this.stack = detectedStack;
    this.findings = [];
  }

  /**
   * Run all authentication security checks
   */
  async analyze() {
    console.error('[Auth] Analyzing authentication security...');

    const checks = [
      this.analyzeJWTSecurity(),
      this.analyzeSessionSecurity(),
      this.analyzePasswordHandling(),
      this.analyzeOAuthConfig(),
      this.analyzeAuthMiddleware(),
    ];

    // Framework-specific auth checks
    if (this.hasAuth('NextAuth.js') || this.hasAuth('Auth.js')) {
      checks.push(this.analyzeNextAuth());
    }
    if (this.hasAuth('Clerk')) {
      checks.push(this.analyzeClerk());
    }
    if (this.hasAuth('Supabase Auth')) {
      checks.push(this.analyzeSupabaseAuth());
    }
    if (this.hasAuth('Firebase Auth')) {
      checks.push(this.analyzeFirebaseAuth());
    }
    if (this.hasAuth('Passport.js')) {
      checks.push(this.analyzePassport());
    }
    if (this.hasAuth('Lucia Auth')) {
      checks.push(this.analyzeLucia());
    }

    await Promise.all(checks);

    return {
      findings: this.findings,
      analyzedAuthProviders: this.stack.auth || []
    };
  }

  hasAuth(provider) {
    return (this.stack.auth || []).some(a =>
      a.toLowerCase().includes(provider.toLowerCase())
    );
  }

  addFinding(finding) {
    this.findings.push({
      category: 'auth-security',
      ...finding
    });
  }

  // ============================================
  // JWT SECURITY ANALYSIS
  // ============================================
  async analyzeJWTSecurity() {
    console.error('[Auth] Checking JWT security...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts', '.py']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for weak JWT secrets
        if (/jwt[._]?secret\s*[:=]\s*['"][^'"]{1,20}['"]/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Weak JWT Secret',
            description: `${relativePath} has a short JWT secret (< 32 chars).`,
            remediation: 'Use at least 32 random characters for JWT secrets.',
            location: { file: relativePath }
          });
        }

        // Check for hardcoded JWT secrets
        if (/(?:jsonwebtoken|jose|jwt).*sign\s*\([^)]*['"][A-Za-z0-9]{8,}['"]/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Hardcoded JWT Secret',
            description: `${relativePath} has a hardcoded JWT signing secret.`,
            remediation: 'Move JWT secret to environment variable.',
            location: { file: relativePath }
          });
        }

        // Check for 'none' algorithm
        if (/algorithm\s*[:=]\s*['"]none['"]/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'JWT "none" Algorithm',
            description: `${relativePath} allows "none" algorithm which bypasses signature.`,
            remediation: 'Never allow "none" algorithm. Use HS256 or RS256.',
            location: { file: relativePath }
          });
        }

        // Check for missing algorithm specification
        if (/jwt\.verify\s*\([^)]*\)/.test(content)) {
          if (!/algorithms?\s*[:=]/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'JWT Verification Missing Algorithm',
              description: `${relativePath} verifies JWT without specifying algorithm.`,
              remediation: 'Always specify algorithms: jwt.verify(token, secret, { algorithms: ["HS256"] })',
              location: { file: relativePath }
            });
          }
        }

        // Check for JWT in URL
        if (/\?.*token=|&token=|\/token\//i.test(content)) {
          if (/jwt|bearer/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'JWT in URL Parameter',
              description: `${relativePath} may pass JWT in URL (logged, cached, referer leak).`,
              remediation: 'Pass tokens in Authorization header, not URL.',
              location: { file: relativePath }
            });
          }
        }

        // Check for JWT stored in localStorage
        if (/localStorage\.setItem\s*\([^)]*(?:jwt|token|accessToken)/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'JWT Stored in localStorage',
            description: `${relativePath} stores JWT in localStorage (XSS accessible).`,
            remediation: 'Store tokens in httpOnly cookies instead.',
            location: { file: relativePath }
          });
        }

        // Check for long JWT expiry
        if (/expiresIn\s*[:=]\s*['"](\d+)d['"]/i.test(content)) {
          const days = parseInt(RegExp.$1);
          if (days > 7) {
            this.addFinding({
              severity: 'medium',
              title: 'Long JWT Expiry',
              description: `${relativePath} sets JWT expiry to ${days} days.`,
              remediation: 'Consider shorter expiry (1-24 hours) with refresh tokens.',
              location: { file: relativePath }
            });
          }
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // SESSION SECURITY ANALYSIS
  // ============================================
  async analyzeSessionSecurity() {
    console.error('[Auth] Checking session security...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check express-session configuration
        if (/express-session|session\s*\(/i.test(content)) {
          // Check for secure: false
          if (/secure\s*:\s*false/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'Session Cookie Not Secure',
              description: `${relativePath} sets session cookie without Secure flag.`,
              remediation: 'Set secure: true for production (HTTPS only).',
              location: { file: relativePath }
            });
          }

          // Check for httpOnly: false
          if (/httpOnly\s*:\s*false/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'Session Cookie Not HttpOnly',
              description: `${relativePath} session cookie accessible via JavaScript.`,
              remediation: 'Set httpOnly: true to prevent XSS access.',
              location: { file: relativePath }
            });
          }

          // Check for missing sameSite
          if (!/sameSite\s*:/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'Session Missing SameSite',
              description: `${relativePath} session doesn't set SameSite attribute.`,
              remediation: 'Set sameSite: "lax" or "strict" to prevent CSRF.',
              location: { file: relativePath }
            });
          }

          // Check for hardcoded session secret
          if (/secret\s*:\s*['"][^'"]+['"]/i.test(content)) {
            if (!/process\.env|env\./i.test(content)) {
              this.addFinding({
                severity: 'critical',
                title: 'Hardcoded Session Secret',
                description: `${relativePath} has hardcoded session secret.`,
                remediation: 'Use environment variable: secret: process.env.SESSION_SECRET',
                location: { file: relativePath }
              });
            }
          }

          // Check for resave and saveUninitialized
          if (!/resave\s*:/i.test(content)) {
            this.addFinding({
              severity: 'low',
              title: 'Session Missing resave Option',
              description: `${relativePath} doesn't specify resave option.`,
              remediation: 'Explicitly set resave: false for most cases.',
              location: { file: relativePath }
            });
          }
        }

        // Check for session fixation vulnerability
        if (/req\.session\s*=|session\s*=.*req/i.test(content)) {
          if (!/regenerate|destroy/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'Possible Session Fixation',
              description: `${relativePath} assigns session without regenerating.`,
              remediation: 'Call req.session.regenerate() after login.',
              location: { file: relativePath }
            });
          }
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // PASSWORD HANDLING ANALYSIS
  // ============================================
  async analyzePasswordHandling() {
    console.error('[Auth] Checking password handling...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts', '.py']);
    let hasBcrypt = false;
    let hasArgon2 = false;

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for password hashing library usage
        if (/bcrypt|bcryptjs/i.test(content)) hasBcrypt = true;
        if (/argon2/i.test(content)) hasArgon2 = true;

        // Check for MD5/SHA1 password hashing
        if (/(?:md5|sha1)\s*\([^)]*password/i.test(content) ||
            /createHash\s*\(\s*['"](?:md5|sha1)['"]\)[^)]*password/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Weak Password Hashing',
            description: `${relativePath} uses MD5/SHA1 for password hashing.`,
            remediation: 'Use bcrypt, scrypt, or Argon2 for password hashing.',
            location: { file: relativePath }
          });
        }

        // Check for plaintext password storage
        if (/password\s*[:=]\s*(?:req\.body|params|query)\.password/i.test(content)) {
          if (!/hash|bcrypt|argon|crypt/i.test(content)) {
            this.addFinding({
              severity: 'critical',
              title: 'Possible Plaintext Password Storage',
              description: `${relativePath} may store passwords without hashing.`,
              remediation: 'Hash passwords before storage: await bcrypt.hash(password, 10)',
              location: { file: relativePath }
            });
          }
        }

        // Check for password in logs
        if (/console\.\w+\s*\([^)]*password/i.test(content) ||
            /log\.\w+\s*\([^)]*password/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'Password in Logs',
            description: `${relativePath} may log passwords.`,
            remediation: 'Never log passwords or sensitive credentials.',
            location: { file: relativePath }
          });
        }

        // Check for bcrypt cost factor
        if (/bcrypt\.hash\s*\([^,]+,\s*(\d+)/i.test(content)) {
          const rounds = parseInt(RegExp.$1);
          if (rounds < 10) {
            this.addFinding({
              severity: 'medium',
              title: 'Low bcrypt Cost Factor',
              description: `${relativePath} uses bcrypt with ${rounds} rounds.`,
              remediation: 'Use at least 10-12 rounds for bcrypt.',
              location: { file: relativePath }
            });
          }
        }

        // Check for password comparison timing attack
        if (/password\s*===|===\s*password/i.test(content)) {
          if (!/bcrypt\.compare|argon2\.verify|timingSafeEqual/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'Password Comparison Timing Attack',
              description: `${relativePath} uses === for password comparison.`,
              remediation: 'Use bcrypt.compare() or crypto.timingSafeEqual().',
              location: { file: relativePath }
            });
          }
        }

      } catch {
        // Skip
      }
    }

    // Check if any password hashing is detected
    if (!hasBcrypt && !hasArgon2) {
      // Check if app handles passwords at all
      const authFiles = await this.findAuthFiles();
      if (authFiles.length > 0) {
        this.addFinding({
          severity: 'high',
          title: 'No Password Hashing Library Detected',
          description: 'Project has auth files but no bcrypt/argon2 detected.',
          remediation: 'Install bcrypt: npm install bcrypt'
        });
      }
    }
  }

  // ============================================
  // OAUTH/OIDC CONFIGURATION
  // ============================================
  async analyzeOAuthConfig() {
    console.error('[Auth] Checking OAuth/OIDC configuration...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for hardcoded client secrets
        if (/client[_-]?secret\s*[:=]\s*['"][A-Za-z0-9_-]{20,}['"]/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Hardcoded OAuth Client Secret',
            description: `${relativePath} has hardcoded OAuth client secret.`,
            remediation: 'Move to environment variable.',
            location: { file: relativePath }
          });
        }

        // Check for state parameter
        if (/oauth|authorize\?/i.test(content)) {
          if (!/state\s*[:=]/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'OAuth Missing State Parameter',
              description: `${relativePath} OAuth flow may lack state parameter.`,
              remediation: 'Add state parameter to prevent CSRF in OAuth.',
              location: { file: relativePath }
            });
          }
        }

        // Check for PKCE
        if (/authorization[_-]?code|auth.*code/i.test(content)) {
          if (!/code[_-]?verifier|code[_-]?challenge|pkce/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'OAuth Missing PKCE',
              description: `${relativePath} uses auth code flow without PKCE.`,
              remediation: 'Implement PKCE for authorization code flow.',
              location: { file: relativePath }
            });
          }
        }

        // Check for open redirect in callback
        if (/callback.*redirect|redirect.*callback/i.test(content)) {
          if (!/whitelist|allowedOrigins|validRedirect/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'OAuth Callback Redirect Validation',
              description: `${relativePath} OAuth callback may not validate redirects.`,
              remediation: 'Validate callback redirect URLs against allowlist.',
              location: { file: relativePath }
            });
          }
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // AUTH MIDDLEWARE ANALYSIS
  // ============================================
  async analyzeAuthMiddleware() {
    console.error('[Auth] Checking auth middleware...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for auth bypass patterns
        if (/isAdmin\s*[:=]\s*(?:req\.|params\.|query\.|body\.)/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Admin Status from User Input',
            description: `${relativePath} sets admin status from request data.`,
            remediation: 'Never trust user input for authorization. Check database/session.',
            location: { file: relativePath }
          });
        }

        // Check for role from JWT without verification
        if (/(?:role|admin|permission)\s*[:=]\s*(?:decoded|payload|token)\./i.test(content)) {
          if (!/verify/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'Role from Unverified Token',
              description: `${relativePath} extracts role without visible verification.`,
              remediation: 'Always verify JWT signature before trusting claims.',
              location: { file: relativePath }
            });
          }
        }

        // Check for missing auth on sensitive routes
        if (/(?:delete|admin|settings|account).*(?:get|post|put|delete)\s*\(/i.test(content)) {
          if (!/auth|protect|guard|middleware|requireAuth|isAuth/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'Sensitive Route May Lack Auth',
              description: `${relativePath} has sensitive route without visible auth check.`,
              remediation: 'Add authentication middleware to sensitive routes.',
              location: { file: relativePath }
            });
          }
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // NEXTAUTH SPECIFIC ANALYSIS
  // ============================================
  async analyzeNextAuth() {
    console.error('[Auth] Checking NextAuth.js configuration...');

    const authFiles = ['auth.ts', 'auth.js', 'pages/api/auth/[...nextauth].ts', 'pages/api/auth/[...nextauth].js', 'app/api/auth/[...nextauth]/route.ts'];

    for (const authFile of authFiles) {
      try {
        const content = await readFile(join(this.projectPath, authFile), 'utf-8');

        // Check for NEXTAUTH_SECRET
        if (/secret\s*:/i.test(content)) {
          if (!/process\.env\.NEXTAUTH_SECRET|env\./i.test(content)) {
            this.addFinding({
              severity: 'critical',
              title: 'NextAuth Secret Not From Environment',
              description: `${authFile} may have hardcoded NEXTAUTH_SECRET.`,
              remediation: 'Use process.env.NEXTAUTH_SECRET',
              location: { file: authFile }
            });
          }
        }

        // Check for debug mode
        if (/debug\s*:\s*true/i.test(content)) {
          this.addFinding({
            severity: 'medium',
            title: 'NextAuth Debug Mode Enabled',
            description: `${authFile} has debug: true.`,
            remediation: 'Disable debug mode in production.',
            location: { file: authFile }
          });
        }

        // Check for session strategy
        if (!/strategy\s*:/i.test(content)) {
          this.addFinding({
            severity: 'info',
            title: 'NextAuth Session Strategy Not Specified',
            description: `${authFile} doesn't explicitly set session strategy.`,
            remediation: 'Explicitly set strategy: "jwt" or "database".',
            location: { file: authFile }
          });
        }

        // Check callbacks security
        if (/callbacks\s*:\s*\{/i.test(content)) {
          if (/jwt.*\{[^}]*\.\.\.token/i.test(content) || /session.*\{[^}]*\.\.\.session/i.test(content)) {
            // Good - using spread
          } else if (/jwt|session/i.test(content) && !/\.\.\.token|\.\.\.session/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'NextAuth Callback May Override Data',
              description: `${authFile} callbacks may not preserve existing data.`,
              remediation: 'Use spread operator: { ...token, customField }',
              location: { file: authFile }
            });
          }
        }

      } catch {
        // File doesn't exist
      }
    }

    // Check for NEXTAUTH_URL in env
    await this.checkEnvVar('NEXTAUTH_URL', 'NextAuth URL not set. Required for production.');
    await this.checkEnvVar('NEXTAUTH_SECRET', 'NextAuth secret not set. Required for production.');
  }

  // ============================================
  // CLERK SPECIFIC ANALYSIS
  // ============================================
  async analyzeClerk() {
    console.error('[Auth] Checking Clerk configuration...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts', '.tsx']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for exposed Clerk secret key
        if (/CLERK_SECRET_KEY/i.test(content)) {
          if (!/process\.env/i.test(content)) {
            this.addFinding({
              severity: 'critical',
              title: 'Clerk Secret Key Exposed',
              description: `${relativePath} may expose Clerk secret key.`,
              remediation: 'Use process.env.CLERK_SECRET_KEY',
              location: { file: relativePath }
            });
          }
        }

        // Check for proper auth checks
        if (/clerkMiddleware|authMiddleware/i.test(content)) {
          if (!/publicRoutes|ignoredRoutes|matcher/i.test(content)) {
            this.addFinding({
              severity: 'info',
              title: 'Clerk Middleware Without Route Config',
              description: `${relativePath} uses Clerk middleware without route config.`,
              remediation: 'Configure publicRoutes or matcher for clarity.',
              location: { file: relativePath }
            });
          }
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // SUPABASE AUTH SPECIFIC ANALYSIS
  // ============================================
  async analyzeSupabaseAuth() {
    console.error('[Auth] Checking Supabase Auth configuration...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts', '.tsx']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for proper session handling
        if (/supabase.*auth/i.test(content)) {
          // Check for getSession vs getUser
          if (/getSession\s*\(\)/i.test(content) && !/getUser\s*\(\)/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'Supabase Using getSession Without getUser',
              description: `${relativePath} uses getSession. Consider getUser for security.`,
              remediation: 'Use getUser() for server-side auth checks (validates JWT).',
              location: { file: relativePath }
            });
          }
        }

        // Check for password requirements
        if (/signUp.*password/i.test(content)) {
          if (!/minLength|password.*length|validate.*password/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'Supabase Signup Without Password Validation',
              description: `${relativePath} signs up without visible password validation.`,
              remediation: 'Add client-side password requirements (length, complexity).',
              location: { file: relativePath }
            });
          }
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // FIREBASE AUTH SPECIFIC ANALYSIS
  // ============================================
  async analyzeFirebaseAuth() {
    console.error('[Auth] Checking Firebase Auth configuration...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts', '.tsx']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for proper token verification
        if (/verifyIdToken/i.test(content)) {
          // Good - using proper verification
        } else if (/currentUser|auth\(\)\.currentUser/i.test(content)) {
          // Check if it's server-side
          if (/api|server|route|handler/i.test(relativePath)) {
            this.addFinding({
              severity: 'high',
              title: 'Firebase Auth Using currentUser Server-Side',
              description: `${relativePath} uses currentUser on server (unreliable).`,
              remediation: 'Use admin.auth().verifyIdToken() for server-side.',
              location: { file: relativePath }
            });
          }
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // PASSPORT.JS SPECIFIC ANALYSIS
  // ============================================
  async analyzePassport() {
    console.error('[Auth] Checking Passport.js configuration...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for serializeUser security
        if (/serializeUser/i.test(content)) {
          if (/done\s*\(\s*null\s*,\s*user\s*\)/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'Passport Serializes Entire User Object',
              description: `${relativePath} serializes full user to session.`,
              remediation: 'Only serialize user.id: done(null, user.id)',
              location: { file: relativePath }
            });
          }
        }

        // Check for password strategy
        if (/LocalStrategy/i.test(content)) {
          if (!/bcrypt|argon|hash/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'Passport Local Strategy Without Hashing',
              description: `${relativePath} LocalStrategy may not hash passwords.`,
              remediation: 'Use bcrypt.compare() in verification callback.',
              location: { file: relativePath }
            });
          }
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // LUCIA AUTH SPECIFIC ANALYSIS
  // ============================================
  async analyzeLucia() {
    console.error('[Auth] Checking Lucia Auth configuration...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for proper session validation
        if (/lucia/i.test(content)) {
          if (/validateSession/i.test(content)) {
            // Good
          } else if (/getSession/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'Lucia Using getSession',
              description: `${relativePath} uses getSession. Consider validateSession.`,
              remediation: 'Use validateSession() for most auth checks.',
              location: { file: relativePath }
            });
          }
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // UTILITY METHODS
  // ============================================
  async getSourceFiles(extensions) {
    const files = [];
    await this.walkDir(this.projectPath, extensions, files);
    return files;
  }

  async walkDir(dir, extensions, files) {
    const skipDirs = ['node_modules', '.git', 'dist', 'build', '.next', '__pycache__', 'venv'];

    try {
      const entries = await readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(dir, entry.name);

        if (entry.isDirectory() && !skipDirs.includes(entry.name)) {
          await this.walkDir(fullPath, extensions, files);
        } else if (entry.isFile() && extensions.includes(extname(entry.name))) {
          files.push(fullPath);
        }
      }
    } catch {
      // Permission error
    }
  }

  async findAuthFiles() {
    const authPatterns = ['auth', 'login', 'signin', 'signup', 'register', 'session'];
    const files = await this.getSourceFiles(['.js', '.ts', '.tsx']);

    return files.filter(f => authPatterns.some(p => f.toLowerCase().includes(p)));
  }

  async checkEnvVar(varName, message) {
    const envFiles = ['.env', '.env.local', '.env.example'];

    for (const envFile of envFiles) {
      try {
        const content = await readFile(join(this.projectPath, envFile), 'utf-8');
        if (content.includes(varName)) {
          return; // Found it
        }
      } catch {
        // File doesn't exist
      }
    }

    this.addFinding({
      severity: 'medium',
      title: `Missing ${varName}`,
      description: message,
      remediation: `Add ${varName} to your .env file.`
    });
  }
}

export default AuthSecurityAnalyzer;
