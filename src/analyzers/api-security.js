/**
 * API Security Analyzer
 *
 * Deep security checks for API implementations:
 * - Input validation
 * - Rate limiting
 * - CORS configuration
 * - Error handling and information disclosure
 * - API authentication
 * - GraphQL specific issues
 * - REST API best practices
 */

import { readFile, readdir } from 'fs/promises';
import { join, extname } from 'path';

export class APISecurityAnalyzer {
  constructor(projectPath, detectedStack) {
    this.projectPath = projectPath;
    this.stack = detectedStack;
    this.findings = [];
  }

  /**
   * Run all API security checks
   */
  async analyze() {
    console.error('[API] Analyzing API security...');

    const checks = [
      this.analyzeInputValidation(),
      this.analyzeRateLimiting(),
      this.analyzeCORS(),
      this.analyzeErrorHandling(),
      this.analyzeAPIAuth(),
      this.analyzeResponseSecurity(),
    ];

    // GraphQL specific checks
    if (this.hasAPI('GraphQL')) {
      checks.push(this.analyzeGraphQL());
    }

    // tRPC specific checks
    if (this.hasAPI('tRPC')) {
      checks.push(this.analyzeTRPC());
    }

    await Promise.all(checks);

    return {
      findings: this.findings,
      analyzedAPIs: this.stack.api || []
    };
  }

  hasAPI(api) {
    return (this.stack.api || []).some(a =>
      a.toLowerCase().includes(api.toLowerCase())
    );
  }

  addFinding(finding) {
    this.findings.push({
      category: 'api-security',
      ...finding
    });
  }

  // ============================================
  // INPUT VALIDATION ANALYSIS
  // ============================================
  async analyzeInputValidation() {
    console.error('[API] Checking input validation...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts']);
    let hasZod = false;
    let hasYup = false;
    let hasJoi = false;

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Detect validation libraries
        if (/from\s+['"]zod['"]/i.test(content)) hasZod = true;
        if (/from\s+['"]yup['"]/i.test(content)) hasYup = true;
        if (/from\s+['"]joi['"]/i.test(content)) hasJoi = true;

        // Check for unvalidated body parsing
        if (/req\.body\./i.test(content)) {
          if (!/z\.|yup\.|joi\.|validate|schema|parse/i.test(content)) {
            // Check if it's an API route
            if (/api|route|handler|controller/i.test(relativePath)) {
              this.addFinding({
                severity: 'high',
                title: 'Unvalidated Request Body',
                description: `${relativePath} uses req.body without visible validation.`,
                remediation: 'Validate all input with Zod, Yup, or Joi before use.',
                location: { file: relativePath }
              });
            }
          }
        }

        // Check for type coercion issues
        if (/parseInt\s*\(\s*req\.|Number\s*\(\s*req\./i.test(content)) {
          if (!/isNaN|isFinite/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'Unsafe Type Coercion',
              description: `${relativePath} coerces request data without NaN check.`,
              remediation: 'Check for isNaN after parseInt/Number, or use validation library.',
              location: { file: relativePath }
            });
          }
        }

        // Check for direct database query with user input
        if (/\.find\s*\(\s*\{[^}]*req\.body/i.test(content) ||
            /\.findOne\s*\(\s*\{[^}]*req\.query/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'User Input Directly in Database Query',
            description: `${relativePath} passes user input directly to database query.`,
            remediation: 'Validate and sanitize input before database queries.',
            location: { file: relativePath }
          });
        }

        // Check for array input without length validation
        if (/req\.body\.\w+\.map|req\.body\.\w+\.forEach/i.test(content)) {
          if (!/length\s*>|\.slice|\.limit|maxLength/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'Array Input Without Length Check',
              description: `${relativePath} iterates array input without length limit.`,
              remediation: 'Add max length validation for array inputs to prevent DoS.',
              location: { file: relativePath }
            });
          }
        }

      } catch {
        // Skip
      }
    }

    // Report if no validation library detected
    if (!hasZod && !hasYup && !hasJoi) {
      const apiFiles = await this.findAPIFiles();
      if (apiFiles.length > 0) {
        this.addFinding({
          severity: 'high',
          title: 'No Input Validation Library Detected',
          description: 'Project has API routes but no Zod/Yup/Joi detected.',
          remediation: 'Install a validation library: npm install zod'
        });
      }
    }
  }

  // ============================================
  // RATE LIMITING ANALYSIS
  // ============================================
  async analyzeRateLimiting() {
    console.error('[API] Checking rate limiting...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts']);
    let hasRateLimiting = false;

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');

        if (/rate[_-]?limit|ratelimit|upstash.*ratelimit|express-rate-limit/i.test(content)) {
          hasRateLimiting = true;
        }
      } catch {
        // Skip
      }
    }

    if (!hasRateLimiting) {
      const apiFiles = await this.findAPIFiles();
      if (apiFiles.length > 0) {
        this.addFinding({
          severity: 'high',
          title: 'No Rate Limiting Detected',
          description: 'API routes exist but no rate limiting is configured.',
          remediation: 'Implement rate limiting with @upstash/ratelimit or express-rate-limit.'
        });
      }
    }

    // Check for specific rate limit configurations
    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for very high rate limits
        if (/(?:max|limit)\s*:\s*(\d+)/i.test(content)) {
          const limit = parseInt(RegExp.$1);
          if (limit > 1000) {
            this.addFinding({
              severity: 'low',
              title: 'High Rate Limit',
              description: `${relativePath} has rate limit of ${limit}, which may be too high.`,
              remediation: 'Consider lower limits for sensitive endpoints.',
              location: { file: relativePath }
            });
          }
        }

        // Check for missing rate limit on auth endpoints
        if (/login|signin|auth|password/i.test(relativePath)) {
          if (!/rate[_-]?limit/i.test(content)) {
            this.addFinding({
              severity: 'critical',
              title: 'Auth Endpoint Without Rate Limiting',
              description: `${relativePath} is an auth endpoint without rate limiting.`,
              remediation: 'Add strict rate limiting to prevent brute force attacks.',
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
  // CORS ANALYSIS
  // ============================================
  async analyzeCORS() {
    console.error('[API] Checking CORS configuration...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for wildcard CORS
        if (/cors\s*\(\s*\)/i.test(content) ||
            /origin\s*:\s*true/i.test(content) ||
            /origin\s*:\s*['"]\*['"]/i.test(content)) {
          this.addFinding({
            severity: 'medium',
            title: 'Permissive CORS Configuration',
            description: `${relativePath} allows CORS from any origin.`,
            remediation: 'Restrict CORS to specific trusted origins.',
            location: { file: relativePath }
          });
        }

        // Check for credentials with wildcard
        if (/credentials\s*:\s*true/i.test(content)) {
          if (/origin\s*:\s*['"]\*['"]/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'CORS Credentials with Wildcard Origin',
              description: `${relativePath} enables credentials with wildcard (browsers block this).`,
              remediation: 'Specify exact origins when using credentials.',
              location: { file: relativePath }
            });
          }
        }

        // Check for CORS header manipulation
        if (/Access-Control-Allow-Origin.*req\.headers\.origin/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'CORS Reflects Request Origin',
            description: `${relativePath} reflects any origin in CORS headers.`,
            remediation: 'Validate origin against an allowlist instead of reflecting.',
            location: { file: relativePath }
          });
        }

      } catch {
        // Skip
      }
    }

    // Check for next.config.js CORS
    try {
      const nextConfig = await readFile(join(this.projectPath, 'next.config.js'), 'utf-8');
      if (/allowedOrigins\s*:\s*\[\s*['"]\*['"]/i.test(nextConfig)) {
        this.addFinding({
          severity: 'medium',
          title: 'Next.js Permissive CORS',
          description: 'next.config.js allows all origins.',
          remediation: 'Specify exact allowed origins.',
          location: { file: 'next.config.js' }
        });
      }
    } catch {
      // No next.config.js
    }
  }

  // ============================================
  // ERROR HANDLING ANALYSIS
  // ============================================
  async analyzeErrorHandling() {
    console.error('[API] Checking error handling...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Skip if not an API file
        if (!/api|route|handler|controller/i.test(relativePath)) continue;

        // Check for exposed stack traces
        if (/res\.(?:json|send)\s*\([^)]*(?:error\.stack|err\.stack|\.stack)/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'Stack Trace Exposed in Response',
            description: `${relativePath} may expose stack traces to clients.`,
            remediation: 'Log errors server-side, return generic error messages to clients.',
            location: { file: relativePath }
          });
        }

        // Check for detailed error messages
        if (/res\.(?:json|send)\s*\([^)]*error\.message/i.test(content)) {
          this.addFinding({
            severity: 'medium',
            title: 'Detailed Error Message Exposed',
            description: `${relativePath} exposes error messages to clients.`,
            remediation: 'Return generic error messages. Log details server-side.',
            location: { file: relativePath }
          });
        }

        // Check for catch blocks without logging
        if (/catch\s*\([^)]*\)\s*\{[^}]*res\./i.test(content)) {
          if (!/console\.|log\.|logger/i.test(content)) {
            this.addFinding({
              severity: 'low',
              title: 'Error Handling Without Logging',
              description: `${relativePath} catches errors without logging.`,
              remediation: 'Log errors for debugging and monitoring.',
              location: { file: relativePath }
            });
          }
        }

        // Check for global error handler
        if (/app\.use\s*\(\s*(?:function\s*\()?(?:err|error)/i.test(content)) {
          // Has error handler - good
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // API AUTHENTICATION ANALYSIS
  // ============================================
  async analyzeAPIAuth() {
    console.error('[API] Checking API authentication...');

    const apiFiles = await this.findAPIFiles();

    for (const file of apiFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Skip public/webhook routes
        if (/webhook|public|health|ping|callback/i.test(relativePath)) continue;

        // Check for API key in URL
        if (/api[_-]?key.*query|query.*api[_-]?key/i.test(content)) {
          this.addFinding({
            severity: 'medium',
            title: 'API Key in URL Parameter',
            description: `${relativePath} accepts API key in URL (logged, cached).`,
            remediation: 'Pass API keys in Authorization header instead.',
            location: { file: relativePath }
          });
        }

        // Check for hardcoded API keys for validation
        if (/(?:req\.|params\.|query\.).*===\s*['"][A-Za-z0-9_-]{20,}['"]/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Hardcoded API Key for Validation',
            description: `${relativePath} compares against hardcoded API key.`,
            remediation: 'Store API keys in environment variables or database.',
            location: { file: relativePath }
          });
        }

        // Check for Bearer token validation
        if (/authorization.*bearer/i.test(content)) {
          if (!/verify|validate|decode.*verify/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'Bearer Token Without Verification',
              description: `${relativePath} reads Bearer token without visible verification.`,
              remediation: 'Always verify JWT tokens before trusting claims.',
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
  // RESPONSE SECURITY ANALYSIS
  // ============================================
  async analyzeResponseSecurity() {
    console.error('[API] Checking response security...');

    const apiFiles = await this.findAPIFiles();

    for (const file of apiFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for sensitive data in responses
        if (/res\.json\s*\(\s*(?:user|account)/i.test(content)) {
          if (/password|secret|hash|token|apiKey/i.test(content)) {
            if (!/delete|omit|exclude|select/i.test(content)) {
              this.addFinding({
                severity: 'high',
                title: 'Sensitive Data in API Response',
                description: `${relativePath} may return sensitive user data.`,
                remediation: 'Filter sensitive fields: delete user.password before responding.',
                location: { file: relativePath }
              });
            }
          }
        }

        // Check for excessive data exposure
        if (/res\.json\s*\(\s*await.*findMany|res\.json\s*\(\s*users/i.test(content)) {
          if (!/take|limit|select|slice/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'API Returns Unbounded Data',
              description: `${relativePath} may return all records without limit.`,
              remediation: 'Add pagination with limit/offset or cursor-based pagination.',
              location: { file: relativePath }
            });
          }
        }

        // Check for internal IDs exposure
        if (/res\.json.*_id|res\.json.*internalId/i.test(content)) {
          this.addFinding({
            severity: 'low',
            title: 'Internal IDs in API Response',
            description: `${relativePath} exposes internal database IDs.`,
            remediation: 'Consider using UUIDs or opaque identifiers for public APIs.',
            location: { file: relativePath }
          });
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // GRAPHQL ANALYSIS
  // ============================================
  async analyzeGraphQL() {
    console.error('[API] Checking GraphQL security...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts', '.graphql', '.gql']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for introspection enabled
        if (/introspection\s*:\s*true/i.test(content)) {
          this.addFinding({
            severity: 'medium',
            title: 'GraphQL Introspection Enabled',
            description: `${relativePath} has introspection enabled.`,
            remediation: 'Disable introspection in production: introspection: false',
            location: { file: relativePath }
          });
        }

        // Check for query depth limiting
        if (/graphql|apollo/i.test(content)) {
          if (!/depthLimit|queryComplexity|maxDepth/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'GraphQL Missing Depth Limiting',
              description: `${relativePath} GraphQL server may lack depth limiting.`,
              remediation: 'Add graphql-depth-limit to prevent deeply nested queries.',
              location: { file: relativePath }
            });
          }
        }

        // Check for query complexity limiting
        if (/apollo.*server|graphql.*yoga/i.test(content)) {
          if (!/queryComplexity|costLimit/i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'GraphQL Missing Complexity Limiting',
              description: `${relativePath} GraphQL lacks query complexity limits.`,
              remediation: 'Add graphql-query-complexity plugin.',
              location: { file: relativePath }
            });
          }
        }

        // Check for dangerous resolvers
        if (/deleteMany|deleteAll|truncate/i.test(content)) {
          if (!/admin|authorized|role/i.test(content)) {
            this.addFinding({
              severity: 'critical',
              title: 'Dangerous GraphQL Mutation',
              description: `${relativePath} has bulk delete without visible auth.`,
              remediation: 'Add admin authorization to dangerous mutations.',
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
  // TRPC ANALYSIS
  // ============================================
  async analyzeTRPC() {
    console.error('[API] Checking tRPC security...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for publicProcedure on sensitive operations
        if (/publicProcedure.*(?:delete|update|create|admin)/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'tRPC Public Procedure for Sensitive Operation',
            description: `${relativePath} uses publicProcedure for mutation.`,
            remediation: 'Use protectedProcedure for create/update/delete operations.',
            location: { file: relativePath }
          });
        }

        // Check for input validation
        if (/\.mutation\s*\(\s*async/i.test(content)) {
          if (!/\.input\s*\(|z\./i.test(content)) {
            this.addFinding({
              severity: 'medium',
              title: 'tRPC Mutation Without Input Validation',
              description: `${relativePath} has mutation without .input() schema.`,
              remediation: 'Add Zod input validation: .input(z.object({...}))',
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

  async findAPIFiles() {
    const files = await this.getSourceFiles(['.js', '.ts']);
    return files.filter(f =>
      /api|route|handler|controller|resolver|trpc/i.test(f)
    );
  }
}

export default APISecurityAnalyzer;
