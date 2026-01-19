/**
 * Database Security Analyzer
 *
 * Deep security checks for specific databases:
 * - Supabase: RLS policies, JWT config, service role exposure
 * - PostgreSQL: Connection security, query patterns
 * - MongoDB: Auth, injection patterns, schema exposure
 * - MySQL: Privileges, injection patterns
 * - Redis: Auth, command restrictions
 */

import { readFile, readdir, access } from 'fs/promises';
import { join, extname } from 'path';

export class DatabaseSecurityAnalyzer {
  constructor(projectPath, detectedStack) {
    this.projectPath = projectPath;
    this.stack = detectedStack;
    this.findings = [];
  }

  /**
   * Run all applicable database checks
   */
  async analyze() {
    const checks = [];

    // Run checks based on detected databases
    if (this.hasDatabase('Supabase')) checks.push(this.analyzeSupabase());
    if (this.hasDatabase('PostgreSQL') || this.hasDatabase('Prisma')) checks.push(this.analyzePostgres());
    if (this.hasDatabase('MongoDB') || this.hasDatabase('Mongoose')) checks.push(this.analyzeMongoDB());
    if (this.hasDatabase('MySQL')) checks.push(this.analyzeMySQL());
    if (this.hasDatabase('Redis') || this.hasDatabase('Upstash Redis')) checks.push(this.analyzeRedis());
    if (this.hasDatabase('Firebase') || this.hasDatabase('Firestore')) checks.push(this.analyzeFirebase());

    // Always run general database security checks
    checks.push(this.analyzeGeneralDatabaseSecurity());

    await Promise.all(checks);

    return {
      findings: this.findings,
      analyzedDatabases: this.getAnalyzedDatabases()
    };
  }

  hasDatabase(db) {
    const allTech = Object.values(this.stack).flat();
    return allTech.some(t => t.toLowerCase().includes(db.toLowerCase()));
  }

  getAnalyzedDatabases() {
    return this.stack.database || [];
  }

  addFinding(finding) {
    this.findings.push({
      category: 'database-security',
      ...finding
    });
  }

  // ============================================
  // SUPABASE SECURITY ANALYSIS
  // ============================================
  async analyzeSupabase() {
    console.error('[Database] Analyzing Supabase security...');

    // Check Supabase config
    await this.checkSupabaseConfig();

    // Check migrations for RLS
    await this.checkSupabaseMigrations();

    // Check for service role key exposure
    await this.checkSupabaseKeyExposure();

    // Check Supabase client usage
    await this.checkSupabaseClientUsage();
  }

  async checkSupabaseConfig() {
    try {
      const config = await readFile(join(this.projectPath, 'supabase/config.toml'), 'utf-8');

      // Check JWT expiry
      const jwtMatch = config.match(/jwt_expiry\s*=\s*(\d+)/);
      if (jwtMatch) {
        const expiry = parseInt(jwtMatch[1]);
        if (expiry > 3600) {
          this.addFinding({
            severity: 'medium',
            title: 'Supabase JWT Expiry Too Long',
            description: `JWT expiry is ${expiry} seconds (${Math.round(expiry / 3600)} hours).`,
            remediation: 'Consider shorter JWT expiry (1 hour or less) for sensitive apps.',
            location: { file: 'supabase/config.toml' }
          });
        }
      }

      // Check for site URL
      if (/site_url\s*=\s*["']http:\/\/localhost/i.test(config)) {
        this.addFinding({
          severity: 'info',
          title: 'Supabase Site URL is Localhost',
          description: 'Site URL is set to localhost. Update for production.',
          remediation: 'Set site_url to your production domain.',
          location: { file: 'supabase/config.toml' }
        });
      }

      // Check for email confirmations
      if (/enable_confirmations\s*=\s*false/i.test(config)) {
        this.addFinding({
          severity: 'medium',
          title: 'Supabase Email Confirmations Disabled',
          description: 'Email confirmations are disabled.',
          remediation: 'Enable email confirmations for production.',
          location: { file: 'supabase/config.toml' }
        });
      }

    } catch {
      // No config file
    }
  }

  async checkSupabaseMigrations() {
    try {
      const migrationsPath = join(this.projectPath, 'supabase/migrations');
      const files = await readdir(migrationsPath);

      const tables = new Map(); // tableName -> { hasRLS: bool, policies: [] }

      for (const file of files.sort()) {
        if (!file.endsWith('.sql')) continue;

        const content = await readFile(join(migrationsPath, file), 'utf-8');

        // Find CREATE TABLE statements
        const tableMatches = [...content.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?["']?(\w+)["']?/gi)];
        for (const match of tableMatches) {
          const tableName = match[1].toLowerCase();
          if (!tables.has(tableName)) {
            tables.set(tableName, { hasRLS: false, policies: [], file });
          }
        }

        // Find ENABLE ROW LEVEL SECURITY
        const rlsMatches = [...content.matchAll(/ALTER\s+TABLE\s+(?:public\.)?["']?(\w+)["']?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi)];
        for (const match of rlsMatches) {
          const tableName = match[1].toLowerCase();
          if (tables.has(tableName)) {
            tables.get(tableName).hasRLS = true;
          }
        }

        // Find CREATE POLICY statements
        const policyMatches = [...content.matchAll(/CREATE\s+POLICY\s+["']?(\w+)["']?\s+ON\s+(?:public\.)?["']?(\w+)["']?/gi)];
        for (const match of policyMatches) {
          const policyName = match[1];
          const tableName = match[2].toLowerCase();
          if (tables.has(tableName)) {
            tables.get(tableName).policies.push(policyName);
          }
        }

        // Check for dangerous patterns in migrations
        if (/SECURITY\s+DEFINER/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'SECURITY DEFINER Function',
            description: `Migration ${file} creates a SECURITY DEFINER function.`,
            remediation: 'SECURITY DEFINER runs as the function owner. Ensure input validation.',
            location: { file: `supabase/migrations/${file}` }
          });
        }

        // Check for grant all
        if (/GRANT\s+ALL\s+ON/i.test(content)) {
          this.addFinding({
            severity: 'medium',
            title: 'GRANT ALL Permissions',
            description: `Migration ${file} grants ALL permissions.`,
            remediation: 'Use least-privilege: grant only specific permissions needed.',
            location: { file: `supabase/migrations/${file}` }
          });
        }
      }

      // Report tables without RLS
      for (const [tableName, info] of tables) {
        // Skip internal tables
        if (['schema_migrations', 'migrations'].includes(tableName)) continue;

        if (!info.hasRLS) {
          this.addFinding({
            severity: 'critical',
            title: `Table "${tableName}" Missing RLS`,
            description: `Table ${tableName} does not have Row Level Security enabled.`,
            remediation: `Add: ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;`,
            location: { file: `supabase/migrations/${info.file}` }
          });
        } else if (info.policies.length === 0) {
          this.addFinding({
            severity: 'high',
            title: `Table "${tableName}" Has RLS But No Policies`,
            description: `RLS is enabled on ${tableName} but no policies defined. All access is blocked.`,
            remediation: 'Create appropriate RLS policies for SELECT, INSERT, UPDATE, DELETE.',
            location: { file: `supabase/migrations/${info.file}` }
          });
        }
      }

    } catch {
      // No migrations directory
    }
  }

  async checkSupabaseKeyExposure() {
    const sourceFiles = await this.getSourceFiles(['.js', '.ts', '.jsx', '.tsx', '.vue', '.svelte']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for service role key in client code
        if (/service[_-]?role|SUPABASE_SERVICE/i.test(content)) {
          // Check if it's in a server file
          const isServerFile = /server|api|route|handler|\.server\.|pages\/api|app\/api/i.test(relativePath);

          if (!isServerFile) {
            this.addFinding({
              severity: 'critical',
              title: 'Supabase Service Role Key in Client Code',
              description: `${relativePath} may expose the service role key.`,
              remediation: 'Service role key should ONLY be used server-side. Use anon key for client.',
              location: { file: relativePath }
            });
          }
        }

        // Check for hardcoded Supabase URL/keys
        if (/https:\/\/[a-z]+\.supabase\.co/i.test(content) &&
            /eyJ[A-Za-z0-9_-]{100,}/i.test(content)) {
          // Check if in environment example file
          if (!/\.example|\.sample|\.template/i.test(relativePath)) {
            this.addFinding({
              severity: 'high',
              title: 'Hardcoded Supabase Credentials',
              description: `${relativePath} has hardcoded Supabase URL and key.`,
              remediation: 'Move to environment variables (NEXT_PUBLIC_SUPABASE_URL, etc.)',
              location: { file: relativePath }
            });
          }
        }

      } catch {
        // Skip
      }
    }
  }

  async checkSupabaseClientUsage() {
    const sourceFiles = await this.getSourceFiles(['.js', '.ts', '.jsx', '.tsx']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for .single() without error handling
        if (/\.single\(\)(?!\s*\.\s*(?:catch|then)|[^;]*(?:error|throw))/i.test(content)) {
          this.addFinding({
            severity: 'low',
            title: 'Supabase .single() Without Error Handling',
            description: `${relativePath} uses .single() which throws if not exactly 1 row.`,
            remediation: 'Use .maybeSingle() or handle the error case.',
            location: { file: relativePath }
          });
        }

        // Check for user-controlled table names
        if (/\.from\s*\(\s*(?:req\.|params\.|query\.|body\.|\$\{)/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Dynamic Table Name in Supabase Query',
            description: `${relativePath} uses user input for table name.`,
            remediation: 'Never use user input for table names. Whitelist allowed tables.',
            location: { file: relativePath }
          });
        }

        // Check for .rpc() with user input
        if (/\.rpc\s*\(\s*(?:\$\{|req\.|params\.|query\.)/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Dynamic RPC Function Name',
            description: `${relativePath} uses user input for RPC function name.`,
            remediation: 'Never use user input for function names. Whitelist allowed functions.',
            location: { file: relativePath }
          });
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // MONGODB SECURITY ANALYSIS
  // ============================================
  async analyzeMongoDB() {
    console.error('[Database] Analyzing MongoDB security...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts', '.py']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for NoSQL injection via operators
        if (/\{\s*\$(?:where|gt|gte|lt|lte|ne|regex|in|nin|or|and|not)\s*:.*(?:req\.|params\.|query\.|body\.)/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'NoSQL Injection - MongoDB Operator',
            description: `${relativePath} passes user input to MongoDB operators.`,
            remediation: 'Sanitize input with mongo-sanitize. Never pass user input to $where.',
            location: { file: relativePath }
          });
        }

        // Check for $where usage
        if (/\$where\s*:/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'MongoDB $where Operator Used',
            description: `${relativePath} uses $where which allows JavaScript execution.`,
            remediation: 'Replace $where with $expr or standard query operators.',
            location: { file: relativePath }
          });
        }

        // Check for connection string in code
        if (/mongodb(?:\+srv)?:\/\/[^/]+:[^@]+@/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'MongoDB Connection String with Credentials',
            description: `${relativePath} has MongoDB connection string with password.`,
            remediation: 'Move to environment variable: process.env.MONGODB_URI',
            location: { file: relativePath }
          });
        }

        // Check for missing authentication
        if (/MongoClient\.connect\s*\([^)]*(?!authSource|auth)/i.test(content)) {
          if (!/process\.env|MONGO.*URI/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'MongoDB Connection Without Auth',
              description: `${relativePath} connects to MongoDB without visible auth.`,
              remediation: 'Ensure authentication is configured in connection string.',
              location: { file: relativePath }
            });
          }
        }

        // Check for eval in aggregation
        if (/\$function|mapReduce/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'MongoDB Server-Side JavaScript',
            description: `${relativePath} uses $function or mapReduce (server-side JS).`,
            remediation: 'Avoid server-side JS. Use aggregation pipeline operators instead.',
            location: { file: relativePath }
          });
        }

        // Mongoose specific checks
        if (/mongoose/i.test(content)) {
          // Check for findByIdAndUpdate without validation
          if (/findByIdAndUpdate|findOneAndUpdate/i.test(content)) {
            if (!/runValidators\s*:\s*true/i.test(content)) {
              this.addFinding({
                severity: 'medium',
                title: 'Mongoose Update Without Validation',
                description: `${relativePath} uses update without runValidators.`,
                remediation: 'Add { runValidators: true } to update operations.',
                location: { file: relativePath }
              });
            }
          }
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // POSTGRESQL SECURITY ANALYSIS
  // ============================================
  async analyzePostgres() {
    console.error('[Database] Analyzing PostgreSQL security...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts', '.py']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for SQL injection patterns
        const sqlInjectionPatterns = [
          /query\s*\(\s*['"`].*\+\s*(?:req\.|params\.|body\.)/i,
          /query\s*\(\s*['"`].*\$\{(?:req\.|params\.|body\.)/i,
          /execute\s*\(\s*f?['"`].*\{(?:req|params|body)/i,
          /\.raw\s*\(\s*['"`].*\$\{/i,
        ];

        for (const pattern of sqlInjectionPatterns) {
          if (pattern.test(content)) {
            this.addFinding({
              severity: 'critical',
              title: 'SQL Injection Vulnerability',
              description: `${relativePath} builds SQL queries with user input.`,
              remediation: 'Use parameterized queries: query("SELECT * FROM users WHERE id = $1", [id])',
              location: { file: relativePath }
            });
            break;
          }
        }

        // Check for connection string exposure
        if (/postgres(?:ql)?:\/\/[^/]+:[^@]+@/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'PostgreSQL Connection String with Password',
            description: `${relativePath} has database connection string with credentials.`,
            remediation: 'Move to environment variable: process.env.DATABASE_URL',
            location: { file: relativePath }
          });
        }

        // Check for dangerous functions
        if (/pg_read_file|pg_ls_dir|pg_stat_file/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'PostgreSQL File Access Function',
            description: `${relativePath} uses PostgreSQL file system functions.`,
            remediation: 'These functions can expose server files. Use with extreme caution.',
            location: { file: relativePath }
          });
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // MYSQL SECURITY ANALYSIS
  // ============================================
  async analyzeMySQL() {
    console.error('[Database] Analyzing MySQL security...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts', '.py', '.php']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for SQL injection
        if (/query\s*\(\s*['"`].*(?:\+\s*(?:req\.|params\.)|%s|%d)/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'MySQL SQL Injection',
            description: `${relativePath} may be vulnerable to SQL injection.`,
            remediation: 'Use prepared statements with placeholders (?).',
            location: { file: relativePath }
          });
        }

        // Check for LOAD DATA INFILE
        if (/LOAD\s+DATA\s+(?:LOCAL\s+)?INFILE/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'MySQL LOAD DATA INFILE',
            description: `${relativePath} uses LOAD DATA INFILE which can read local files.`,
            remediation: 'Disable LOAD DATA LOCAL or ensure input is trusted.',
            location: { file: relativePath }
          });
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // REDIS SECURITY ANALYSIS
  // ============================================
  async analyzeRedis() {
    console.error('[Database] Analyzing Redis security...');

    const sourceFiles = await this.getSourceFiles(['.js', '.ts', '.py']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for EVAL command
        if (/\.eval\s*\(|EVAL\s+/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'Redis EVAL Command Used',
            description: `${relativePath} uses Redis EVAL which runs Lua scripts.`,
            remediation: 'Ensure EVAL scripts are predefined, never from user input.',
            location: { file: relativePath }
          });
        }

        // Check for KEYS command
        if (/\.keys\s*\(|KEYS\s+/i.test(content)) {
          this.addFinding({
            severity: 'medium',
            title: 'Redis KEYS Command Used',
            description: `${relativePath} uses KEYS which blocks Redis and can be slow.`,
            remediation: 'Use SCAN instead of KEYS for production.',
            location: { file: relativePath }
          });
        }

        // Check for DEBUG commands
        if (/DEBUG\s+(?:SEGFAULT|SLEEP|CRASH)/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Redis DEBUG Command',
            description: `${relativePath} uses dangerous Redis DEBUG commands.`,
            remediation: 'Remove DEBUG commands. They should be disabled in production.',
            location: { file: relativePath }
          });
        }

        // Check for connection without auth
        if (/createClient\s*\(\s*\{[^}]*url\s*:/i.test(content)) {
          if (!/password|username|REDIS.*URL/i.test(content)) {
            this.addFinding({
              severity: 'high',
              title: 'Redis Connection Without Auth',
              description: `${relativePath} connects to Redis without visible auth.`,
              remediation: 'Use password authentication for Redis.',
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
  // FIREBASE SECURITY ANALYSIS
  // ============================================
  async analyzeFirebase() {
    console.error('[Database] Analyzing Firebase security...');

    // Check Firestore rules
    await this.checkFirestoreRules();

    // Check for exposed config
    await this.checkFirebaseConfig();
  }

  async checkFirestoreRules() {
    const rulesFiles = ['firestore.rules', 'firebase/firestore.rules'];

    for (const rulesFile of rulesFiles) {
      try {
        const content = await readFile(join(this.projectPath, rulesFile), 'utf-8');

        // Check for open rules
        if (/allow\s+read\s*,\s*write\s*:\s*if\s+true/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Firestore Rules Allow All',
            description: 'Firestore rules allow read/write for everyone.',
            remediation: 'Implement proper security rules based on authentication.',
            location: { file: rulesFile }
          });
        }

        // Check for missing authentication check
        if (!/request\.auth\s*!=\s*null/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'Firestore Rules May Not Check Authentication',
            description: 'No request.auth != null check found in rules.',
            remediation: 'Add authentication checks: allow read: if request.auth != null',
            location: { file: rulesFile }
          });
        }

      } catch {
        // No rules file
      }
    }
  }

  async checkFirebaseConfig() {
    const sourceFiles = await this.getSourceFiles(['.js', '.ts', '.jsx', '.tsx']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Check for exposed service account
        if (/type.*service_account|private_key.*-----BEGIN/i.test(content)) {
          this.addFinding({
            severity: 'critical',
            title: 'Firebase Service Account in Code',
            description: `${relativePath} may contain Firebase service account credentials.`,
            remediation: 'Move service account to server-side only. Use environment variables.',
            location: { file: relativePath }
          });
        }

      } catch {
        // Skip
      }
    }
  }

  // ============================================
  // GENERAL DATABASE SECURITY
  // ============================================
  async analyzeGeneralDatabaseSecurity() {
    console.error('[Database] Running general database security checks...');

    // Check environment files
    await this.checkDatabaseEnvVars();

    // Check for database URLs in code
    await this.checkDatabaseUrls();
  }

  async checkDatabaseEnvVars() {
    const envFiles = ['.env', '.env.local', '.env.development', '.env.production'];

    for (const envFile of envFiles) {
      try {
        const content = await readFile(join(this.projectPath, envFile), 'utf-8');

        // Check for weak database passwords
        const dbPasswordPatterns = [
          /DATABASE.*PASSWORD\s*=\s*(?:password|123|admin|root|test)/i,
          /MONGO.*PASSWORD\s*=\s*(?:password|123|admin|root|test)/i,
          /REDIS.*PASSWORD\s*=\s*(?:password|123|admin|root|test)/i,
        ];

        for (const pattern of dbPasswordPatterns) {
          if (pattern.test(content)) {
            this.addFinding({
              severity: 'critical',
              title: 'Weak Database Password',
              description: `${envFile} contains a weak database password.`,
              remediation: 'Use a strong, randomly generated password.',
              location: { file: envFile }
            });
            break;
          }
        }

        // Check for localhost database URLs in production env
        if (envFile.includes('production') && /DATABASE.*localhost|127\.0\.0\.1/i.test(content)) {
          this.addFinding({
            severity: 'high',
            title: 'Production Env Uses Localhost Database',
            description: `${envFile} has localhost database URL.`,
            remediation: 'Update to production database URL.',
            location: { file: envFile }
          });
        }

      } catch {
        // File doesn't exist
      }
    }
  }

  async checkDatabaseUrls() {
    const sourceFiles = await this.getSourceFiles(['.js', '.ts', '.py']);

    for (const file of sourceFiles) {
      try {
        const content = await readFile(file, 'utf-8');
        const relativePath = file.replace(this.projectPath, '');

        // Skip env example files
        if (/\.example|\.sample|\.template/i.test(relativePath)) continue;

        // Check for hardcoded database URLs with credentials
        const dbUrlPatterns = [
          /(?:postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@(?!localhost|127\.0\.0\.1)[^\s'"]+/i,
        ];

        for (const pattern of dbUrlPatterns) {
          if (pattern.test(content)) {
            this.addFinding({
              severity: 'critical',
              title: 'Database URL with Credentials in Code',
              description: `${relativePath} contains a database URL with embedded password.`,
              remediation: 'Move to environment variable. Never commit credentials.',
              location: { file: relativePath }
            });
            break;
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
    const skipDirs = ['node_modules', '.git', 'dist', 'build', '.next', '__pycache__', 'venv', '.venv'];

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
}

export default DatabaseSecurityAnalyzer;
