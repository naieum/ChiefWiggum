/**
 * Framework-Specific Security Analyzers
 *
 * Deep security analysis tailored to specific frameworks:
 * - React/Next.js
 * - Express/Fastify/Node APIs
 * - Django/Flask/FastAPI
 * - Vue/Nuxt
 * - And more...
 */

import { readFile, readdir } from 'fs/promises';
import { join, extname, basename } from 'path';

export class FrameworkSecurityAnalyzer {
  constructor(projectPath, detectedStack) {
    this.projectPath = projectPath;
    this.stack = detectedStack;
    this.findings = [];
  }

  /**
   * Run all applicable framework checks
   */
  async analyze() {
    const checks = [];

    // Frontend frameworks
    if (this.hasStack('Next.js')) checks.push(this.analyzeNextJs());
    if (this.hasStack('React')) checks.push(this.analyzeReact());
    if (this.hasStack('Vue.js') || this.hasStack('Nuxt.js')) checks.push(this.analyzeVue());
    if (this.hasStack('Angular')) checks.push(this.analyzeAngular());
    if (this.hasStack('Svelte') || this.hasStack('SvelteKit')) checks.push(this.analyzeSvelte());

    // Backend frameworks
    if (this.hasStack('Express.js')) checks.push(this.analyzeExpress());
    if (this.hasStack('Fastify')) checks.push(this.analyzeFastify());
    if (this.hasStack('NestJS')) checks.push(this.analyzeNestJS());
    if (this.hasStack('Django')) checks.push(this.analyzeDjango());
    if (this.hasStack('Flask')) checks.push(this.analyzeFlask());
    if (this.hasStack('FastAPI')) checks.push(this.analyzeFastAPI());

    // ORMs
    if (this.hasStack('Prisma')) checks.push(this.analyzePrisma());
    if (this.hasStack('Drizzle')) checks.push(this.analyzeDrizzle());

    await Promise.all(checks);

    return {
      findings: this.findings,
      analyzedFrameworks: this.getAnalyzedFrameworks()
    };
  }

  hasStack(tech) {
    return Object.values(this.stack).flat().includes(tech);
  }

  getAnalyzedFrameworks() {
    return Object.values(this.stack).flat();
  }

  addFinding(finding) {
    this.findings.push({
      category: 'framework-specific',
      ...finding
    });
  }

  // ============================================
  // NEXT.JS SECURITY ANALYSIS
  // ============================================
  async analyzeNextJs() {
    console.error('[Framework] Analyzing Next.js security...');

    // Check next.config.js
    for (const configFile of ['next.config.js', 'next.config.mjs', 'next.config.ts']) {
      try {
        const content = await readFile(join(this.projectPath, configFile), 'utf-8');

        // Check for disabled security headers
        if (/poweredByHeader\s*:\s*true/i.test(content)) {
          this.addFinding({
            severity: 'low',
            title: 'Next.js X-Powered-By Header Enabled',
            description: 'The X-Powered-By header reveals your tech stack.',
            remediation: 'Set poweredByHeader: false in next.config.js',
            location: { file: configFile }
          });
        }

        // Check for permissive image domains
        if (/domains\s*:\s*\[\s*['"][*'"]/i.test(content) || /remotePatterns.*\*\*/i.test(content)) {
          this.addFinding({
            severity: 'medium',
            title: 'Permissive Image Domain Configuration',
            description: 'Wildcard image domains can allow loading malicious images.',
            remediation: 'Specify exact domains in next.config.js images.domains',
            location: { file: configFile }
          });
        }

        // Check for disabled strict mode
        if (/reactStrictMode\s*:\s*false/i.test(content)) {
          this.addFinding({
            severity: 'info',
            title: 'React Strict Mode Disabled',
            description: 'Strict mode helps identify potential problems.',
            remediation: 'Set reactStrictMode: true in next.config.js',
            location: { file: configFile }
          });
        }

      } catch {
        // Config doesn't exist
      }
    }

    // Check for exposed API routes
    await this.checkNextApiRoutes();

    // Check for unsafe getServerSideProps patterns
    await this.checkNextDataFetching();

    // Check middleware security
    await this.checkNextMiddleware();
  }

  async checkNextApiRoutes() {
    const apiPaths = ['pages/api', 'app/api', 'src/pages/api', 'src/app/api'];

    for (const apiPath of apiPaths) {
      const files = await this.getFilesRecursive(join(this.projectPath, apiPath));

      for (const file of files) {
        try {
          const content = await readFile(file, 'utf-8');
          const relativePath = file.replace(this.projectPath, '');

          // Check for missing authentication
          if (!/getSession|getServerSession|getToken|auth\(|withAuth|requireAuth/i.test(content)) {
            // Check if it's a public route (webhooks, health checks, etc.)
            if (!/webhook|health|ping|public/i.test(relativePath)) {
              this.addFinding({
                severity: 'high',
                title: 'API Route Missing Authentication',
                description: `API route ${relativePath} may not have authentication checks.`,
                remediation: 'Add authentication using getServerSession, getToken, or middleware.',
                location: { file: relativePath }
              });
            }
          }

          // Check for missing rate limiting
          if (!/rateLimit|rateLimiter|upstash.*ratelimit/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'API Route Missing Rate Limiting',
              description: `API route ${relativePath} has no rate limiting.`,
              remediation: 'Implement rate limiting using @upstash/ratelimit or similar.',
              location: { file: relativePath }
            });
          }

          // Check for dangerous request handling
          if (/req\.body\s*\[|req\.query\s*\[/.test(content) && !/zod|yup|joi|validate/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'Unvalidated Request Input',
              description: `API route ${relativePath} uses request data without apparent validation.`,
              remediation: 'Validate all input using Zod, Yup, or Joi schemas.',
              location: { file: relativePath }
            });
          }

          // Check for SQL in API routes
          if (/\$\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE)|query\s*\(.*\+/i.test(content)) {
            this.addFinding({
              severity: 'critical',
              title: 'Potential SQL Injection in API Route',
              description: `API route ${relativePath} may have SQL injection vulnerability.`,
              remediation: 'Use parameterized queries or an ORM like Prisma.',
              location: { file: relativePath }
            });
          }

        } catch {
          // Skip unreadable files
        }
      }
    }
  }

  async checkNextDataFetching() {
    const pagePaths = ['pages', 'app', 'src/pages', 'src/app'];

    for (const pagePath of pagePaths) {
      const files = await this.getFilesRecursive(join(this.projectPath, pagePath));

      for (const file of files) {
        if (!file.endsWith('.tsx') && !file.endsWith('.ts') && !file.endsWith('.js')) continue;

        try {
          const content = await readFile(file, 'utf-8');
          const relativePath = file.replace(this.projectPath, '');

          // Check for exposed secrets in getServerSideProps/getStaticProps
          if (/getServerSideProps|getStaticProps/.test(content)) {
            if (/process\.env\.(?!NEXT_PUBLIC)/i.test(content)) {
              // This is actually fine for server-side, but check if it's returned
              if (/return\s*\{[^}]*props:[^}]*process\.env\./i.test(content)) {
                this.addFinding({
                  severity: 'critical',
                  title: 'Environment Variable Exposed to Client',
                  description: `Server-side env var may be passed to client in ${relativePath}`,
                  remediation: 'Never include server env vars in props. Use API routes instead.',
                  location: { file: relativePath }
                });
              }
            }
          }

          // Check for unprotected server actions (App Router)
          if (/['"]use server['"]/i.test(content)) {
            if (!/getServerSession|auth\(|requireAuth|session/i.test(content)) {
              this.addFinding({
                severity: 'high',
                title: 'Server Action Missing Authentication',
                description: `Server action in ${relativePath} may lack auth checks.`,
                remediation: 'Add authentication checks at the start of server actions.',
                location: { file: relativePath }
              });
            }
          }

        } catch {
          // Skip
        }
      }
    }
  }

  async checkNextMiddleware() {
    const middlewareFiles = ['middleware.ts', 'middleware.js', 'src/middleware.ts', 'src/middleware.js'];

    for (const mwFile of middlewareFiles) {
      try {
        const content = await readFile(join(this.projectPath, mwFile), 'utf-8');

        // Check for proper matcher config
        if (!/matcher\s*:/i.test(content)) {
          this.addFinding({
            severity: 'medium',
            title: 'Middleware Missing Matcher',
            description: 'Middleware runs on all routes without a matcher config.',
            remediation: 'Add a matcher config to specify which routes need protection.',
            location: { file: mwFile }
          });
        }

        // Check for auth in middleware
        if (!/getToken|getSession|auth|NextAuth|clerk/i.test(content)) {
          this.addFinding({
            severity: 'info',
            title: 'Middleware Without Auth Check',
            description: 'Middleware exists but may not include authentication checks.',
            remediation: 'Consider adding auth checks in middleware for protected routes.',
            location: { file: mwFile }
          });
        }

      } catch {
        // No middleware - might want to suggest adding it
      }
    }
  }

  // ============================================
  // REACT SECURITY ANALYSIS
  // ============================================
  async analyzeReact() {
    console.error('[Framework] Analyzing React security...');

    const jsxFiles = await this.getFilesRecursive(this.projectPath, ['.jsx', '.tsx']);

    for (const file of jsxFiles.slice(0, 200)) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for dangerouslySetInnerHTML
        if (/dangerouslySetInnerHTML/i.test(content)) {
          // Check if DOMPurify is used
          if (!/DOMPurify|sanitize|purify/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'dangerouslySetInnerHTML Without Sanitization',
              description: `${relativePath} uses dangerouslySetInnerHTML without apparent sanitization.`,
              remediation: 'Use DOMPurify.sanitize() before setting inner HTML.',
              location: { file: relativePath }
            });
          }
        }

        // Check for href javascript:
        if (/href\s*=\s*\{.*javascript:/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'Unsafe href with javascript:',
            description: `${relativePath} may have XSS via javascript: in href.`,
            remediation: 'Validate URLs and block javascript: protocol.',
            location: { file: relativePath }
          });
        }

        // Check for eval or Function constructor
        if (/\beval\s*\(|new\s+Function\s*\(/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Dynamic Code Execution',
            description: `${relativePath} uses eval() or Function constructor.`,
            remediation: 'Remove eval/Function. Use safer alternatives like JSON.parse.',
            location: { file: relativePath }
          });
        }

        // Check for localStorage sensitive data
        if (/localStorage\.setItem\s*\([^)]*(?:token|password|secret|key|jwt)/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'Sensitive Data in localStorage',
            description: `${relativePath} stores sensitive data in localStorage (XSS-accessible).`,
            remediation: 'Use httpOnly cookies for tokens. localStorage is accessible via XSS.',
            location: { file: relativePath }
          });
        }

        // Check for exposed API keys
        if (/(?:api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9_-]{20,}['"]/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Hardcoded API Key in Component',
            description: `${relativePath} contains a hardcoded API key.`,
            remediation: 'Move to environment variables (NEXT_PUBLIC_ or VITE_).',
            location: { file: relativePath }
          });
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // EXPRESS.JS SECURITY ANALYSIS
  // ============================================
  async analyzeExpress() {
    console.error('[Framework] Analyzing Express.js security...');

    const jsFiles = await this.getFilesRecursive(this.projectPath, ['.js', '.ts']);

    let hasHelmet = false;
    let hasCors = false;
    let hasRateLimit = false;

    for (const file of jsFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for security middleware
        if (/require\s*\(\s*['"]helmet['"]\)|import.*helmet/i.test(content)) hasHelmet = true;
        if (/require\s*\(\s*['"]cors['"]\)|import.*cors/i.test(content)) hasCors = true;
        if (/require\s*\(\s*['"]express-rate-limit['"]\)|rateLimit/i.test(content)) hasRateLimit = true;

        // Check for unsafe body parsing
        if (/express\.json\s*\(\s*\)/.test(content) && !/limit\s*:/i.test(content)) {
          this.addFinding({
            severity: 'medium',
            title: 'Express Body Parser Without Limit',
            description: `${relativePath} uses express.json() without size limit.`,
            remediation: 'Add limit: express.json({ limit: "10kb" })',
            location: { file: relativePath }
          });
        }

        // Check for SQL injection
        if (/query\s*\(\s*['"`].*\$\{|query\s*\(\s*['"`].*\+\s*(?:req\.|params\.|body\.)/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'SQL Injection Vulnerability',
            description: `${relativePath} constructs SQL queries with user input.`,
            remediation: 'Use parameterized queries: query("SELECT * FROM users WHERE id = $1", [id])',
            location: { file: relativePath }
          });
        }

        // Check for path traversal
        if (/sendFile\s*\(.*(?:req\.|params\.|query\.)|readFile\s*\(.*(?:req\.|params\.)/i.test(content)) {
          if (!/path\.resolve|path\.normalize|\.\..*reject|sanitize/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'Potential Path Traversal',
              description: `${relativePath} uses user input in file operations.`,
              remediation: 'Validate paths with path.resolve() and check they stay within allowed directories.',
              location: { file: relativePath }
            });
          }
        }

        // Check for open redirect
        if (/res\.redirect\s*\(.*(?:req\.|params\.|query\.)/i.test(content)) {
          this.addFinding({
            severity: 'medium',
            title: 'Potential Open Redirect',
            description: `${relativePath} redirects using user-controlled input.`,
            remediation: 'Validate redirect URLs against an allowlist of trusted domains.',
            location: { file: relativePath }
          });
        }

        // Check for sensitive data in logs
        if (/console\.\w+\s*\(.*(?:password|token|secret|apikey)/i.test(content)) {
          this.addFinding({
            severity: 'medium',
            title: 'Sensitive Data in Logs',
            description: `${relativePath} may log sensitive information.`,
            remediation: 'Remove sensitive data from logs or use redaction.',
            location: { file: relativePath }
          });
        }

      } catch {
        // Skip
      }
    }

    // Report missing security middleware
    if (!hasHelmet) {
      this.addFinding({
        severity: 'high',
        title: 'Missing Helmet.js Security Middleware',
        description: 'Helmet.js sets security-related HTTP headers.',
        remediation: 'Install and use helmet: npm install helmet && app.use(helmet())'
      });
    }

    if (!hasRateLimit) {
      this.addFinding({
        severity: 'high',
        title: 'Missing Rate Limiting',
        description: 'No rate limiting detected. APIs are vulnerable to brute force.',
        remediation: 'Install express-rate-limit: npm install express-rate-limit'
      });
    }
  }

  // ============================================
  // FASTIFY SECURITY ANALYSIS
  // ============================================
  async analyzeFastify() {
    console.error('[Framework] Analyzing Fastify security...');

    const jsFiles = await this.getFilesRecursive(this.projectPath, ['.js', '.ts']);

    for (const file of jsFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for missing schema validation
        if (/fastify\.(get|post|put|delete|patch)\s*\(/i.test(content)) {
          if (!/schema\s*:/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'Fastify Route Missing Schema Validation',
              description: `${relativePath} has routes without schema validation.`,
              remediation: 'Add JSON schema validation for all route inputs.',
              location: { file: relativePath }
            });
          }
        }

        // Check for @fastify/helmet
        if (/require.*fastify|import.*fastify/i.test(content)) {
          if (!/@fastify\/helmet|fastify-helmet/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'Missing Fastify Helmet Plugin',
              description: 'Consider using @fastify/helmet for security headers.',
              remediation: 'npm install @fastify/helmet && fastify.register(helmet)'
            });
          }
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // NESTJS SECURITY ANALYSIS
  // ============================================
  async analyzeNestJS() {
    console.error('[Framework] Analyzing NestJS security...');

    const tsFiles = await this.getFilesRecursive(this.projectPath, ['.ts']);

    let hasGuards = false;
    let hasValidation = false;

    for (const file of tsFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        if (/@UseGuards|AuthGuard|CanActivate/i.test(content)) hasGuards = true;
        if (/@IsString|@IsNumber|class-validator|ValidationPipe/i.test(content)) hasValidation = true;

        // Check for unprotected controllers
        if (/@Controller\s*\(/i.test(content)) {
          if (!/@UseGuards/i.test(content) && !/@Public/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'NestJS Controller Without Guards',
              description: `Controller in ${relativePath} has no authentication guards.`,
              remediation: 'Add @UseGuards(AuthGuard) or mark routes as @Public explicitly.',
              location: { file: relativePath }
            });
          }
        }

        // Check for missing DTO validation
        if (/@Body\s*\(\s*\)/i.test(content) && !/@IsString|@IsNumber|@ValidateNested/i.test(content)) {
          this.addFinding({
            severity: 'medium',
            title: 'Missing DTO Validation',
            description: `${relativePath} accepts body input without class-validator decorators.`,
            remediation: 'Create DTOs with class-validator decorators for all inputs.',
            location: { file: relativePath }
          });
        }

      } catch {
        // Skip
      }
    }

    if (!hasValidation) {
      this.addFinding({
        severity: 'high',
        title: 'NestJS Missing Global Validation',
        description: 'No ValidationPipe detected. Input validation may be missing.',
        remediation: 'Add app.useGlobalPipes(new ValidationPipe()) in main.ts'
      });
    }
  }

  // ============================================
  // DJANGO SECURITY ANALYSIS
  // ============================================
  async analyzeDjango() {
    console.error('[Framework] Analyzing Django security...');

    // Check settings.py
    const settingsFiles = ['settings.py', 'config/settings.py', 'core/settings.py', 'app/settings.py'];

    for (const settingsFile of settingsFiles) {
      try {
        const content = await readFile(join(this.projectPath, settingsFile), 'utf-8');

        // Check DEBUG
        if (/DEBUG\s*=\s*True/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Django DEBUG Mode Enabled',
            description: 'DEBUG=True exposes sensitive information in production.',
            remediation: 'Set DEBUG=False in production settings.',
            location: { file: settingsFile }
          });
        }

        // Check SECRET_KEY
        if (/SECRET_KEY\s*=\s*['"][^'"]+['"]/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Django SECRET_KEY Hardcoded',
            description: 'SECRET_KEY should not be in source code.',
            remediation: 'Use environment variables: SECRET_KEY = os.environ.get("SECRET_KEY")',
            location: { file: settingsFile }
          });
        }

        // Check ALLOWED_HOSTS
        if (/ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'Django ALLOWED_HOSTS Wildcard',
            description: 'ALLOWED_HOSTS = ["*"] allows any host.',
            remediation: 'Specify exact allowed hostnames.',
            location: { file: settingsFile }
          });
        }

        // Check CSRF
        if (/CSRF_COOKIE_SECURE\s*=\s*False|CSRF_TRUSTED_ORIGINS.*\*/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'Django CSRF Misconfiguration',
            description: 'CSRF protection may be weakened.',
            remediation: 'Set CSRF_COOKIE_SECURE=True and restrict CSRF_TRUSTED_ORIGINS.',
            location: { file: settingsFile }
          });
        }

      } catch {
        // Settings file doesn't exist in this location
      }
    }
  }

  // ============================================
  // FLASK SECURITY ANALYSIS
  // ============================================
  async analyzeFlask() {
    console.error('[Framework] Analyzing Flask security...');

    const pyFiles = await this.getFilesRecursive(this.projectPath, ['.py']);

    for (const file of pyFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for debug mode
        if (/app\.run\s*\(.*debug\s*=\s*True/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Flask Debug Mode Enabled',
            description: `${relativePath} runs Flask with debug=True.`,
            remediation: 'Remove debug=True for production.',
            location: { file: relativePath }
          });
        }

        // Check for hardcoded secret key
        if (/app\.secret_key\s*=\s*['"][^'"]+['"]/i.test(content) ||
            /SECRET_KEY\s*=\s*['"][^'"]+['"]/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Flask Secret Key Hardcoded',
            description: `${relativePath} has hardcoded secret key.`,
            remediation: 'Use environment variable: app.secret_key = os.environ.get("SECRET_KEY")',
            location: { file: relativePath }
          });
        }

        // Check for SQL injection
        if (/execute\s*\([^)]*%|cursor\.execute\s*\(.*\+/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'SQL Injection in Flask',
            description: `${relativePath} builds SQL queries with string formatting.`,
            remediation: 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
            location: { file: relativePath }
          });
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // FASTAPI SECURITY ANALYSIS
  // ============================================
  async analyzeFastAPI() {
    console.error('[Framework] Analyzing FastAPI security...');

    const pyFiles = await this.getFilesRecursive(this.projectPath, ['.py']);

    let hasAuthDeps = false;

    for (const file of pyFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        if (/Depends\s*\(.*(?:auth|get_current_user|verify_token)/i.test(content)) {
          hasAuthDeps = true;
        }

        // Check for unprotected routes
        if (/@app\.(get|post|put|delete|patch)\s*\(/i.test(content)) {
          if (!/Depends\s*\(|dependencies\s*=/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'FastAPI Route Without Dependencies',
              description: `${relativePath} has routes without dependency injection.`,
              remediation: 'Add authentication via Depends() for protected routes.',
              location: { file: relativePath }
            });
          }
        }

        // Check for missing response model
        if (/@app\.(get|post).*\n[^r]*return\s+\{/i.test(content)) {
          if (!/response_model\s*=/i.test(content)) {
            this.addFinding({
              severity: 'low',
              title: 'FastAPI Missing Response Model',
              description: `${relativePath} returns dict without response_model.`,
              remediation: 'Define Pydantic models for responses to prevent data leakage.',
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
  // VUE/NUXT SECURITY ANALYSIS
  // ============================================
  async analyzeVue() {
    console.error('[Framework] Analyzing Vue/Nuxt security...');

    const vueFiles = await this.getFilesRecursive(this.projectPath, ['.vue', '.js', '.ts']);

    for (const file of vueFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for v-html
        if (/v-html\s*=/i.test(content)) {
          if (!/sanitize|DOMPurify|purify/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'Vue v-html Without Sanitization',
              description: `${relativePath} uses v-html without sanitization.`,
              remediation: 'Use DOMPurify before rendering with v-html.',
              location: { file: relativePath }
            });
          }
        }

        // Check for exposed secrets in client code
        if (/(?<!NUXT_PUBLIC_)(?:API_KEY|SECRET|TOKEN)\s*[:=]\s*['"][A-Za-z0-9]{16,}/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Exposed Secret in Vue Component',
            description: `${relativePath} may contain hardcoded secrets.`,
            remediation: 'Move to server-side environment variables.',
            location: { file: relativePath }
          });
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // ANGULAR SECURITY ANALYSIS
  // ============================================
  async analyzeAngular() {
    console.error('[Framework] Analyzing Angular security...');

    const tsFiles = await this.getFilesRecursive(this.projectPath, ['.ts']);

    for (const file of tsFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for bypassSecurityTrust*
        if (/bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'Angular Security Bypass Used',
            description: `${relativePath} uses bypassSecurityTrust which can lead to XSS.`,
            remediation: 'Avoid bypassSecurityTrust. Sanitize input at the source instead.',
            location: { file: relativePath }
          });
        }

        // Check for [innerHTML]
        if (/\[innerHTML\]\s*=/i.test(content)) {
          this.addFinding({
            severity: 'medium',
            title: 'Angular innerHTML Binding',
            description: `${relativePath} uses [innerHTML] which can be XSS-prone.`,
            remediation: 'Use Angular sanitization or avoid innerHTML for user content.',
            location: { file: relativePath }
          });
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // SVELTE SECURITY ANALYSIS
  // ============================================
  async analyzeSvelte() {
    console.error('[Framework] Analyzing Svelte security...');

    const svelteFiles = await this.getFilesRecursive(this.projectPath, ['.svelte']);

    for (const file of svelteFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for @html
        if (/@html\s/i.test(content)) {
          if (!/sanitize|DOMPurify/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'Svelte @html Without Sanitization',
              description: `${relativePath} uses @html without sanitization.`,
              remediation: 'Sanitize with DOMPurify before using @html.',
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
  // PRISMA SECURITY ANALYSIS
  // ============================================
  async analyzePrisma() {
    console.error('[Framework] Analyzing Prisma security...');

    try {
      const schema = await readFile(join(this.projectPath, 'prisma/schema.prisma'), 'utf-8');

      // Check for missing @default on sensitive fields
      if (/model\s+User[\s\S]*?password\s+String(?!\s+@)/i.test(schema)) {
        // This is fine, just noting schema review
      }

      // Check database URL in schema
      if (/url\s*=\s*["'][^"']*password/i.test(schema)) {
        this.addFinding({
          severity: 'critical',
          title: 'Database Password in Prisma Schema',
          description: 'Database URL with password is in schema.prisma.',
          remediation: 'Use env("DATABASE_URL") instead of hardcoding.',
          location: { file: 'prisma/schema.prisma' }
        });
      }

    } catch {
      // No Prisma schema
    }

    // Check for raw queries
    const jsFiles = await this.getFilesRecursive(this.projectPath, ['.js', '.ts']);

    for (const file of jsFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        if (/prisma\.\$queryRaw|prisma\.\$executeRaw/i.test(content)) {
          if (/\$queryRaw`[^`]*\$\{|\$executeRaw`[^`]*\$\{/i.test(content)) {
            this.addFinding({
              severity: 'critical',
              title: 'SQL Injection in Prisma Raw Query',
              description: `${relativePath} interpolates variables in raw Prisma query.`,
              remediation: 'Use Prisma.sql tagged template or parameterized queries.',
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
  // DRIZZLE SECURITY ANALYSIS
  // ============================================
  async analyzeDrizzle() {
    console.error('[Framework] Analyzing Drizzle ORM security...');

    const jsFiles = await this.getFilesRecursive(this.projectPath, ['.js', '.ts']);

    for (const file of jsFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for raw SQL
        if (/sql`[^`]*\$\{/i.test(content) || /sql\.raw\s*\(/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'Raw SQL in Drizzle Query',
            description: `${relativePath} uses raw SQL which may be vulnerable.`,
            remediation: 'Use Drizzle query builders instead of raw SQL where possible.',
            location: { file: relativePath }
          });
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // UTILITY METHODS
  // ============================================
  async getFilesRecursive(dir, extensions = null, files = []) {
    const skipDirs = ['node_modules', '.git', 'dist', 'build', '.next', '__pycache__', 'venv', '.venv'];

    try {
      const entries = await readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(dir, entry.name);

        if (entry.isDirectory() && !skipDirs.includes(entry.name)) {
          await this.getFilesRecursive(fullPath, extensions, files);
        } else if (entry.isFile()) {
          if (!extensions || extensions.includes(extname(entry.name))) {
            files.push(fullPath);
          }
        }
      }
    } catch {
      // Permission error
    }

    return files;
  }
}

export default FrameworkSecurityAnalyzer;
