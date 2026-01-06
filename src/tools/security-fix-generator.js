/**
 * Security Fix Generator
 *
 * Auto-generates code patches for common vulnerabilities.
 * Provides copy-paste ready fixes.
 */

import { readFile } from 'fs/promises';
import { join } from 'path';

export class SecurityFixGenerator {
  constructor(projectPath) {
    this.projectPath = projectPath;
  }

  /**
   * Generate fix for a finding
   */
  async generateFix(finding) {
    const category = finding.category || this.detectCategory(finding);

    switch (category) {
      case 'sqlInjection':
        return this.generateSQLInjectionFix(finding);
      case 'nosqlInjection':
        return this.generateNoSQLInjectionFix(finding);
      case 'xssRisks':
        return this.generateXSSFix(finding);
      case 'hardcodedSecrets':
        return this.generateSecretsFix(finding);
      case 'codeExecution':
        return this.generateCodeExecutionFix(finding);
      case 'missingAuth':
        return this.generateAuthFix(finding);
      case 'missingRateLimit':
        return this.generateRateLimitFix(finding);
      case 'insecureHeaders':
        return this.generateHeadersFix(finding);
      case 'dependency':
      case 'live-cve':
        return this.generateDependencyFix(finding);
      default:
        return this.generateGenericFix(finding);
    }
  }

  /**
   * Detect category from finding
   */
  detectCategory(finding) {
    const title = finding.title?.toLowerCase() || '';
    const desc = finding.description?.toLowerCase() || '';
    const combined = title + ' ' + desc;

    if (combined.includes('sql injection')) return 'sqlInjection';
    if (combined.includes('nosql') || combined.includes('mongo')) return 'nosqlInjection';
    if (combined.includes('xss') || combined.includes('innerhtml')) return 'xssRisks';
    if (combined.includes('secret') || combined.includes('password') || combined.includes('key')) return 'hardcodedSecrets';
    if (combined.includes('eval') || combined.includes('exec')) return 'codeExecution';
    if (combined.includes('auth')) return 'missingAuth';
    if (combined.includes('rate limit')) return 'missingRateLimit';
    if (combined.includes('header')) return 'insecureHeaders';
    if (combined.includes('cve') || combined.includes('vulnerability')) return 'dependency';

    return 'generic';
  }

  /**
   * Generate SQL injection fix
   */
  generateSQLInjectionFix(finding) {
    const file = finding.location?.file || 'unknown';

    return {
      title: 'SQL Injection Fix',
      severity: finding.severity,
      location: file,
      explanation: `
SQL Injection occurs when user input is directly concatenated into SQL queries.
The fix is to use parameterized queries (prepared statements) instead.
      `.trim(),

      vulnerablePattern: `
// VULNERABLE - Never do this!
const query = \`SELECT * FROM users WHERE id = '\${userId}'\`;
db.query(query);
      `.trim(),

      fixedPattern: `
// FIXED - Use parameterized queries
const query = 'SELECT * FROM users WHERE id = $1';
db.query(query, [userId]);
      `.trim(),

      frameworks: {
        postgresql: {
          name: 'PostgreSQL (pg)',
          fix: `
// Using pg (node-postgres)
const { rows } = await pool.query(
  'SELECT * FROM users WHERE id = $1 AND status = $2',
  [userId, status]
);
          `.trim()
        },
        mysql: {
          name: 'MySQL',
          fix: `
// Using mysql2
const [rows] = await connection.execute(
  'SELECT * FROM users WHERE id = ? AND status = ?',
  [userId, status]
);
          `.trim()
        },
        prisma: {
          name: 'Prisma ORM',
          fix: `
// Using Prisma - automatically parameterized
const user = await prisma.user.findUnique({
  where: { id: userId }
});

// For raw queries, use Prisma.sql
const users = await prisma.$queryRaw(
  Prisma.sql\`SELECT * FROM users WHERE id = \${userId}\`
);
          `.trim()
        },
        drizzle: {
          name: 'Drizzle ORM',
          fix: `
// Using Drizzle - automatically parameterized
const user = await db
  .select()
  .from(users)
  .where(eq(users.id, userId));
          `.trim()
        }
      },

      test: `
// Security test for SQL injection
describe('SQL Injection Prevention', () => {
  it('should prevent SQL injection in user lookup', async () => {
    const maliciousId = "1'; DROP TABLE users; --";

    // Should not throw or execute malicious SQL
    const response = await request(app)
      .get(\`/api/users/\${encodeURIComponent(maliciousId)}\`)
      .expect(400); // or 404, depending on validation

    // Verify database is intact
    const count = await db.query('SELECT COUNT(*) FROM users');
    expect(count.rows[0].count).toBeGreaterThan(0);
  });
});
      `.trim()
    };
  }

  /**
   * Generate NoSQL injection fix
   */
  generateNoSQLInjectionFix(finding) {
    return {
      title: 'NoSQL Injection Fix',
      severity: finding.severity,
      location: finding.location?.file || 'unknown',
      explanation: `
NoSQL Injection occurs when user input is used directly in MongoDB queries,
especially with operators like $where, $regex, $gt, etc.
      `.trim(),

      vulnerablePattern: `
// VULNERABLE - User can inject operators
const user = await db.users.findOne({ username: req.body.username });
// Attacker sends: { "username": { "$gt": "" } } - matches all users!
      `.trim(),

      fixedPattern: `
// FIXED - Sanitize input and validate types
import mongoSanitize from 'express-mongo-sanitize';
app.use(mongoSanitize()); // Strips $ operators from req.body

// Or manually validate:
const username = String(req.body.username); // Force string type
const user = await db.users.findOne({ username });
      `.trim(),

      frameworks: {
        mongoose: {
          name: 'Mongoose',
          fix: `
// Using mongoose with strict schema
const userSchema = new Schema({
  username: { type: String, required: true }
});

// Query - Mongoose casts to string
const user = await User.findOne({
  username: req.body.username // Mongoose casts this
});

// For extra safety:
const user = await User.findOne({
  username: String(req.body.username)
});
          `.trim()
        },
        mongodb: {
          name: 'MongoDB Native Driver',
          fix: `
// Validate and sanitize
function sanitizeInput(input) {
  if (typeof input !== 'string') {
    throw new Error('Invalid input type');
  }
  return input;
}

const user = await collection.findOne({
  username: sanitizeInput(req.body.username)
});
          `.trim()
        }
      },

      test: `
describe('NoSQL Injection Prevention', () => {
  it('should prevent operator injection', async () => {
    const response = await request(app)
      .post('/api/login')
      .send({ username: { $gt: '' }, password: 'test' })
      .expect(400);

    expect(response.body.error).toContain('Invalid');
  });
});
      `.trim()
    };
  }

  /**
   * Generate XSS fix
   */
  generateXSSFix(finding) {
    return {
      title: 'XSS Prevention Fix',
      severity: finding.severity,
      location: finding.location?.file || 'unknown',
      explanation: `
XSS (Cross-Site Scripting) occurs when user input is rendered as HTML without sanitization.
The fix depends on context: use textContent for text, or sanitize for rich HTML.
      `.trim(),

      vulnerablePattern: `
// VULNERABLE - Directly inserting user HTML
element.innerHTML = userInput;
document.write(userInput);
dangerouslySetInnerHTML={{ __html: userInput }}
      `.trim(),

      fixedPattern: `
// FIXED - Escape or sanitize
element.textContent = userInput; // For plain text

// For rich HTML content, use DOMPurify
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);

// React - avoid dangerouslySetInnerHTML or sanitize
dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }}
      `.trim(),

      frameworks: {
        react: {
          name: 'React',
          fix: `
// React automatically escapes text content
function SafeComponent({ userInput }) {
  return <div>{userInput}</div>; // Safe - auto-escaped
}

// For rich HTML, sanitize:
import DOMPurify from 'dompurify';

function RichContent({ htmlContent }) {
  const clean = DOMPurify.sanitize(htmlContent, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p'],
    ALLOWED_ATTR: ['href']
  });
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
          `.trim()
        },
        nextjs: {
          name: 'Next.js',
          fix: `
// Server Components - same rules apply
import DOMPurify from 'isomorphic-dompurify';

export default function Page({ content }) {
  // For plain text - safe
  return <p>{content}</p>;

  // For HTML - sanitize
  const clean = DOMPurify.sanitize(content);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
          `.trim()
        },
        express: {
          name: 'Express (EJS/Pug)',
          fix: `
// EJS - use <%= for escaped, <%- for raw
<p><%= userInput %></p>  // Safe - escaped
<p><%- userInput %></p>  // DANGEROUS - raw

// Pug - use = for escaped, != for raw
p= userInput   // Safe - escaped
p!= userInput  // DANGEROUS - raw

// For API responses, set proper content-type
res.setHeader('Content-Type', 'application/json');
res.json({ data: userInput });
          `.trim()
        }
      },

      additionalMeasures: `
// Additional XSS prevention measures:

// 1. Content Security Policy header
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self'"
  );
  next();
});

// 2. X-XSS-Protection header (legacy browsers)
res.setHeader('X-XSS-Protection', '1; mode=block');

// 3. Validate and sanitize on input
import validator from 'validator';
const safeInput = validator.escape(userInput);
      `.trim(),

      test: `
describe('XSS Prevention', () => {
  it('should escape HTML in user content', () => {
    const malicious = '<script>alert("xss")</script>';
    const rendered = renderUserContent(malicious);

    expect(rendered).not.toContain('<script>');
    expect(rendered).toContain('&lt;script&gt;');
  });
});
      `.trim()
    };
  }

  /**
   * Generate hardcoded secrets fix
   */
  generateSecretsFix(finding) {
    const key = finding.location?.key || 'SECRET_KEY';

    return {
      title: 'Hardcoded Secrets Fix',
      severity: finding.severity,
      location: finding.location?.file || 'unknown',
      explanation: `
Hardcoded secrets in source code can be exposed through version control,
build artifacts, or client-side bundles. Move all secrets to environment variables.
      `.trim(),

      vulnerablePattern: `
// VULNERABLE - Secret in code
const apiKey = 'sk-1234567890abcdef';
const dbPassword = 'supersecret123';
      `.trim(),

      fixedPattern: `
// FIXED - Use environment variables
const apiKey = process.env.API_KEY;
const dbPassword = process.env.DB_PASSWORD;

// Validate at startup
if (!process.env.API_KEY) {
  throw new Error('API_KEY environment variable is required');
}
      `.trim(),

      steps: [
        {
          step: 1,
          title: 'Create .env file',
          code: `
# .env (DO NOT COMMIT)
${key}=your-secret-value-here
          `.trim()
        },
        {
          step: 2,
          title: 'Add to .gitignore',
          code: `
# Add to .gitignore
.env
.env.local
.env.*.local
          `.trim()
        },
        {
          step: 3,
          title: 'Create .env.example',
          code: `
# .env.example (COMMIT THIS)
${key}=your-${key.toLowerCase().replace(/_/g, '-')}-here
          `.trim()
        },
        {
          step: 4,
          title: 'Update code',
          code: `
// Load environment variables (if not using framework)
import 'dotenv/config';

// Use the variable
const secret = process.env.${key};
if (!secret) {
  throw new Error('${key} is required');
}
          `.trim()
        },
        {
          step: 5,
          title: 'Rotate the exposed secret',
          description: 'Generate a new secret and update it in your production environment. The old secret may be compromised.'
        }
      ],

      frameworks: {
        nextjs: {
          name: 'Next.js',
          note: 'Use NEXT_PUBLIC_ prefix only for client-side variables',
          code: `
// Server-side (API routes, Server Components)
const secret = process.env.${key}; // Not exposed to client

// Client-side (only if needed!)
const publicKey = process.env.NEXT_PUBLIC_API_KEY; // Exposed to client
          `.trim()
        },
        vite: {
          name: 'Vite',
          note: 'Use VITE_ prefix for client-accessible variables',
          code: `
// Server-side
const secret = process.env.${key};

// Client-side (only if needed!)
const publicKey = import.meta.env.VITE_PUBLIC_KEY;
          `.trim()
        }
      },

      test: `
describe('Secret Security', () => {
  it('should not expose secrets in client bundle', async () => {
    const bundle = await readFile('./dist/client.js', 'utf-8');

    expect(bundle).not.toMatch(/sk-[a-zA-Z0-9]+/);
    expect(bundle).not.toMatch(/password/i);
    expect(bundle).not.toContain(process.env.${key});
  });
});
      `.trim()
    };
  }

  /**
   * Generate code execution fix
   */
  generateCodeExecutionFix(finding) {
    return {
      title: 'Code Execution Vulnerability Fix',
      severity: finding.severity,
      location: finding.location?.file || 'unknown',
      explanation: `
eval(), Function(), and similar constructs can execute arbitrary code.
Never use them with user input. Replace with safe alternatives.
      `.trim(),

      vulnerablePattern: `
// VULNERABLE - Arbitrary code execution
eval(userInput);
new Function(userInput)();
setTimeout(userInput, 1000);
child_process.exec(userCommand);
      `.trim(),

      fixedPattern: `
// FIXED - Use safe alternatives

// Instead of eval for JSON:
const data = JSON.parse(userInput);

// Instead of eval for math:
import { evaluate } from 'mathjs';
const result = evaluate(expression, { scope: {} });

// Instead of exec, use execFile with fixed command:
import { execFile } from 'child_process';
execFile('/usr/bin/command', [sanitizedArg], callback);
      `.trim(),

      alternatives: {
        json: {
          problem: 'Parsing JSON with eval',
          solution: 'JSON.parse(input)'
        },
        math: {
          problem: 'Evaluating math expressions',
          solution: 'Use mathjs or expr-eval library'
        },
        template: {
          problem: 'Dynamic template rendering',
          solution: 'Use a sandboxed template engine'
        },
        command: {
          problem: 'Running shell commands',
          solution: 'Use execFile with fixed command and validated args'
        }
      },

      test: `
describe('Code Execution Prevention', () => {
  it('should not execute injected code', () => {
    const malicious = 'process.exit(1)';

    // Should not crash the process
    expect(() => {
      parseUserExpression(malicious);
    }).toThrow(); // or return error
  });
});
      `.trim()
    };
  }

  /**
   * Generate auth fix
   */
  generateAuthFix(finding) {
    return {
      title: 'Authentication Fix',
      severity: finding.severity,
      location: finding.location?.file || 'unknown',
      explanation: `
Authentication ensures that users are who they claim to be.
Every protected endpoint needs authentication middleware.
      `.trim(),

      frameworks: {
        nextjs: {
          name: 'Next.js App Router',
          fix: `
// middleware.ts - Protect routes
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const token = request.cookies.get('session');

  if (!token && request.nextUrl.pathname.startsWith('/dashboard')) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/dashboard/:path*', '/api/protected/:path*']
};
          `.trim()
        },
        express: {
          name: 'Express',
          fix: `
// auth middleware
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const user = verifyToken(token);
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Apply to routes
app.get('/api/protected', requireAuth, (req, res) => {
  res.json({ user: req.user });
});
          `.trim()
        }
      },

      test: `
describe('Authentication', () => {
  it('should reject unauthenticated requests', async () => {
    const response = await request(app)
      .get('/api/protected')
      .expect(401);

    expect(response.body.error).toContain('Authentication');
  });

  it('should reject invalid tokens', async () => {
    const response = await request(app)
      .get('/api/protected')
      .set('Authorization', 'Bearer invalid-token')
      .expect(401);
  });
});
      `.trim()
    };
  }

  /**
   * Generate rate limit fix
   */
  generateRateLimitFix(finding) {
    return {
      title: 'Rate Limiting Fix',
      severity: finding.severity,
      location: finding.location?.file || 'unknown',
      explanation: `
Rate limiting prevents abuse by limiting how many requests a client can make.
Essential for login endpoints, APIs, and any resource-intensive operations.
      `.trim(),

      frameworks: {
        express: {
          name: 'Express',
          fix: `
import rateLimit from 'express-rate-limit';

// General API rate limit
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: { error: 'Too many requests, try again later' }
});

// Strict limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 attempts per hour
  message: { error: 'Too many login attempts' }
});

app.use('/api/', apiLimiter);
app.use('/api/auth/', authLimiter);
          `.trim()
        },
        nextjs: {
          name: 'Next.js',
          fix: `
// Using upstash/ratelimit for serverless
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '10 s'),
});

export async function POST(request: Request) {
  const ip = request.headers.get('x-forwarded-for') ?? '127.0.0.1';
  const { success } = await ratelimit.limit(ip);

  if (!success) {
    return Response.json(
      { error: 'Too many requests' },
      { status: 429 }
    );
  }

  // Handle request...
}
          `.trim()
        }
      },

      test: `
describe('Rate Limiting', () => {
  it('should rate limit after threshold', async () => {
    // Make requests up to limit
    for (let i = 0; i < 100; i++) {
      await request(app).get('/api/endpoint').expect(200);
    }

    // Next request should be rate limited
    const response = await request(app)
      .get('/api/endpoint')
      .expect(429);

    expect(response.body.error).toContain('Too many');
  });
});
      `.trim()
    };
  }

  /**
   * Generate security headers fix
   */
  generateHeadersFix(finding) {
    return {
      title: 'Security Headers Fix',
      severity: finding.severity,
      location: finding.location?.file || 'unknown',

      frameworks: {
        express: {
          name: 'Express (using Helmet)',
          fix: `
import helmet from 'helmet';

app.use(helmet()); // Adds all security headers

// Or configure individually:
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
  },
}));
          `.trim()
        },
        nextjs: {
          name: 'Next.js',
          fix: `
// next.config.js
const securityHeaders = [
  {
    key: 'X-DNS-Prefetch-Control',
    value: 'on'
  },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=31536000; includeSubDomains'
  },
  {
    key: 'X-Frame-Options',
    value: 'SAMEORIGIN'
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff'
  },
  {
    key: 'Referrer-Policy',
    value: 'origin-when-cross-origin'
  },
  {
    key: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self'"
  }
];

module.exports = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: securityHeaders,
      },
    ];
  },
};
          `.trim()
        }
      }
    };
  }

  /**
   * Generate dependency fix
   */
  generateDependencyFix(finding) {
    const pkg = finding.location?.package || 'unknown';
    const fixedVersion = finding.location?.fixedVersion;

    return {
      title: 'Vulnerable Dependency Fix',
      severity: finding.severity,
      package: pkg,
      currentVersion: finding.location?.version || finding.location?.installedVersion,
      fixedVersion: fixedVersion || 'latest',

      commands: {
        npm: fixedVersion
          ? `npm install ${pkg}@${fixedVersion}`
          : `npm update ${pkg}`,
        yarn: fixedVersion
          ? `yarn add ${pkg}@${fixedVersion}`
          : `yarn upgrade ${pkg}`,
        pnpm: fixedVersion
          ? `pnpm add ${pkg}@${fixedVersion}`
          : `pnpm update ${pkg}`
      },

      steps: [
        `1. Update the package: npm install ${pkg}@${fixedVersion || 'latest'}`,
        '2. Run tests to ensure compatibility: npm test',
        '3. Check for breaking changes in the changelog',
        '4. Commit the updated package.json and lock file'
      ],

      checkCommand: 'npm audit',
      verifyCommand: `npm list ${pkg}`
    };
  }

  /**
   * Generate generic fix
   */
  generateGenericFix(finding) {
    return {
      title: `Fix: ${finding.title}`,
      severity: finding.severity,
      location: finding.location?.file || 'unknown',
      description: finding.description,
      remediation: finding.remediation || 'See finding details for remediation steps.',

      generalSteps: [
        '1. Understand the vulnerability and its impact',
        '2. Write a test that exposes the vulnerability',
        '3. Implement the fix',
        '4. Verify the test passes',
        '5. Re-run the security scan to confirm fix'
      ]
    };
  }
}

export default SecurityFixGenerator;
