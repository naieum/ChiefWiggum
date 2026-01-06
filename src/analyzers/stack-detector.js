/**
 * Tech Stack Detector
 *
 * Exhaustively scans a project to identify all technologies in use:
 * - Frontend frameworks (React, Vue, Angular, Svelte, etc.)
 * - Backend frameworks (Express, Fastify, Django, Flask, etc.)
 * - Databases (Supabase, MongoDB, Postgres, MySQL, Redis, etc.)
 * - Authentication (NextAuth, Passport, Clerk, Auth0, etc.)
 * - Cloud services (AWS, GCP, Azure, Vercel, etc.)
 * - Build tools, CI/CD, and more
 */

import { readFile, readdir, access, stat } from 'fs/promises';
import { join, extname } from 'path';

export class StackDetector {
  constructor(projectPath) {
    this.projectPath = projectPath;
    this.detectedStack = {
      frontend: [],
      backend: [],
      database: [],
      auth: [],
      cloud: [],
      api: [],
      testing: [],
      build: [],
      security: [],
      other: []
    };
    this.confidence = {};
    this.configFiles = {};
    this.sourcePatterns = {};
  }

  /**
   * Run full stack detection
   */
  async detect() {
    console.error('[StackDetector] Starting comprehensive stack detection...');

    // Run all detection methods in parallel
    await Promise.all([
      this.analyzePackageJson(),
      this.analyzeRequirementsTxt(),
      this.analyzeConfigFiles(),
      this.analyzeSourceCode(),
      this.analyzeDockerFiles(),
      this.analyzeGitHistory(),
      this.analyzeCICD(),
    ]);

    // Calculate confidence scores
    this.calculateConfidence();

    return {
      stack: this.detectedStack,
      confidence: this.confidence,
      configFiles: this.configFiles,
      summary: this.generateSummary()
    };
  }

  /**
   * Analyze package.json for Node.js projects
   */
  async analyzePackageJson() {
    try {
      const content = await readFile(join(this.projectPath, 'package.json'), 'utf-8');
      const pkg = JSON.parse(content);
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

      this.configFiles['package.json'] = true;

      // Frontend Frameworks
      const frontendMap = {
        'react': { name: 'React', category: 'frontend' },
        'react-dom': { name: 'React', category: 'frontend' },
        'next': { name: 'Next.js', category: 'frontend' },
        'vue': { name: 'Vue.js', category: 'frontend' },
        'nuxt': { name: 'Nuxt.js', category: 'frontend' },
        '@angular/core': { name: 'Angular', category: 'frontend' },
        'svelte': { name: 'Svelte', category: 'frontend' },
        '@sveltejs/kit': { name: 'SvelteKit', category: 'frontend' },
        'solid-js': { name: 'Solid.js', category: 'frontend' },
        'astro': { name: 'Astro', category: 'frontend' },
        'remix': { name: 'Remix', category: 'frontend' },
        '@remix-run/react': { name: 'Remix', category: 'frontend' },
        'gatsby': { name: 'Gatsby', category: 'frontend' },
        'preact': { name: 'Preact', category: 'frontend' },
      };

      // Backend Frameworks
      const backendMap = {
        'express': { name: 'Express.js', category: 'backend' },
        'fastify': { name: 'Fastify', category: 'backend' },
        'koa': { name: 'Koa', category: 'backend' },
        'hapi': { name: 'Hapi', category: 'backend' },
        '@hapi/hapi': { name: 'Hapi', category: 'backend' },
        'nestjs': { name: 'NestJS', category: 'backend' },
        '@nestjs/core': { name: 'NestJS', category: 'backend' },
        'hono': { name: 'Hono', category: 'backend' },
        'elysia': { name: 'Elysia', category: 'backend' },
        'drizzle-orm': { name: 'Drizzle ORM', category: 'backend' },
        'prisma': { name: 'Prisma', category: 'backend' },
        '@prisma/client': { name: 'Prisma', category: 'backend' },
        'typeorm': { name: 'TypeORM', category: 'backend' },
        'sequelize': { name: 'Sequelize', category: 'backend' },
        'mongoose': { name: 'Mongoose', category: 'backend' },
        'knex': { name: 'Knex.js', category: 'backend' },
      };

      // Databases
      const databaseMap = {
        '@supabase/supabase-js': { name: 'Supabase', category: 'database' },
        'supabase': { name: 'Supabase', category: 'database' },
        'pg': { name: 'PostgreSQL', category: 'database' },
        'postgres': { name: 'PostgreSQL', category: 'database' },
        'mongodb': { name: 'MongoDB', category: 'database' },
        'mongoose': { name: 'MongoDB', category: 'database' },
        'mysql': { name: 'MySQL', category: 'database' },
        'mysql2': { name: 'MySQL', category: 'database' },
        'sqlite3': { name: 'SQLite', category: 'database' },
        'better-sqlite3': { name: 'SQLite', category: 'database' },
        'redis': { name: 'Redis', category: 'database' },
        'ioredis': { name: 'Redis', category: 'database' },
        '@upstash/redis': { name: 'Upstash Redis', category: 'database' },
        '@planetscale/database': { name: 'PlanetScale', category: 'database' },
        'firebase': { name: 'Firebase', category: 'database' },
        'firebase-admin': { name: 'Firebase', category: 'database' },
        '@firebase/firestore': { name: 'Firestore', category: 'database' },
        'dynamodb': { name: 'DynamoDB', category: 'database' },
        '@aws-sdk/client-dynamodb': { name: 'DynamoDB', category: 'database' },
        'fauna': { name: 'FaunaDB', category: 'database' },
        'faunadb': { name: 'FaunaDB', category: 'database' },
      };

      // Authentication
      const authMap = {
        'next-auth': { name: 'NextAuth.js', category: 'auth' },
        '@auth/core': { name: 'Auth.js', category: 'auth' },
        'passport': { name: 'Passport.js', category: 'auth' },
        '@clerk/nextjs': { name: 'Clerk', category: 'auth' },
        '@clerk/clerk-js': { name: 'Clerk', category: 'auth' },
        'auth0': { name: 'Auth0', category: 'auth' },
        '@auth0/auth0-react': { name: 'Auth0', category: 'auth' },
        '@auth0/nextjs-auth0': { name: 'Auth0', category: 'auth' },
        'firebase-auth': { name: 'Firebase Auth', category: 'auth' },
        '@supabase/auth-helpers-nextjs': { name: 'Supabase Auth', category: 'auth' },
        'jsonwebtoken': { name: 'JWT (manual)', category: 'auth' },
        'jose': { name: 'JWT (jose)', category: 'auth' },
        'bcrypt': { name: 'bcrypt', category: 'auth' },
        'bcryptjs': { name: 'bcrypt.js', category: 'auth' },
        'argon2': { name: 'Argon2', category: 'auth' },
        'lucia': { name: 'Lucia Auth', category: 'auth' },
        'lucia-auth': { name: 'Lucia Auth', category: 'auth' },
        '@lucia-auth/adapter-prisma': { name: 'Lucia Auth', category: 'auth' },
        'kinde-auth-nextjs': { name: 'Kinde', category: 'auth' },
      };

      // API & Data Fetching
      const apiMap = {
        'axios': { name: 'Axios', category: 'api' },
        'node-fetch': { name: 'node-fetch', category: 'api' },
        '@tanstack/react-query': { name: 'TanStack Query', category: 'api' },
        'swr': { name: 'SWR', category: 'api' },
        'graphql': { name: 'GraphQL', category: 'api' },
        '@apollo/client': { name: 'Apollo Client', category: 'api' },
        'apollo-server': { name: 'Apollo Server', category: 'api' },
        'trpc': { name: 'tRPC', category: 'api' },
        '@trpc/server': { name: 'tRPC', category: 'api' },
        '@trpc/client': { name: 'tRPC', category: 'api' },
        'zod': { name: 'Zod', category: 'api' },
        'yup': { name: 'Yup', category: 'api' },
        'joi': { name: 'Joi', category: 'api' },
      };

      // Cloud & Deployment
      const cloudMap = {
        '@aws-sdk/client-s3': { name: 'AWS S3', category: 'cloud' },
        'aws-sdk': { name: 'AWS SDK', category: 'cloud' },
        '@google-cloud/storage': { name: 'Google Cloud Storage', category: 'cloud' },
        '@azure/storage-blob': { name: 'Azure Blob Storage', category: 'cloud' },
        '@vercel/analytics': { name: 'Vercel', category: 'cloud' },
        '@vercel/og': { name: 'Vercel', category: 'cloud' },
        'netlify-cli': { name: 'Netlify', category: 'cloud' },
        '@cloudflare/workers-types': { name: 'Cloudflare Workers', category: 'cloud' },
        'wrangler': { name: 'Cloudflare Workers', category: 'cloud' },
      };

      // Testing
      const testingMap = {
        'jest': { name: 'Jest', category: 'testing' },
        'vitest': { name: 'Vitest', category: 'testing' },
        'mocha': { name: 'Mocha', category: 'testing' },
        'cypress': { name: 'Cypress', category: 'testing' },
        'playwright': { name: 'Playwright', category: 'testing' },
        '@playwright/test': { name: 'Playwright', category: 'testing' },
        '@testing-library/react': { name: 'Testing Library', category: 'testing' },
      };

      // Security packages
      const securityMap = {
        'helmet': { name: 'Helmet.js', category: 'security' },
        'cors': { name: 'CORS middleware', category: 'security' },
        'csurf': { name: 'CSRF protection', category: 'security' },
        'express-rate-limit': { name: 'Rate limiting', category: 'security' },
        'hpp': { name: 'HPP (HTTP Parameter Pollution)', category: 'security' },
        'xss-clean': { name: 'XSS Clean', category: 'security' },
        'express-mongo-sanitize': { name: 'Mongo Sanitize', category: 'security' },
        'sanitize-html': { name: 'HTML Sanitizer', category: 'security' },
        'dompurify': { name: 'DOMPurify', category: 'security' },
      };

      // Combine all maps
      const allMaps = [
        frontendMap, backendMap, databaseMap, authMap,
        apiMap, cloudMap, testingMap, securityMap
      ];

      // Detect from dependencies
      for (const depName of Object.keys(allDeps)) {
        for (const map of allMaps) {
          if (map[depName]) {
            const { name, category } = map[depName];
            if (!this.detectedStack[category].includes(name)) {
              this.detectedStack[category].push(name);
            }
          }
        }
      }

      // Detect TypeScript
      if (allDeps['typescript']) {
        this.detectedStack.build.push('TypeScript');
      }

      // Detect build tools
      if (allDeps['vite']) this.detectedStack.build.push('Vite');
      if (allDeps['webpack']) this.detectedStack.build.push('Webpack');
      if (allDeps['esbuild']) this.detectedStack.build.push('esbuild');
      if (allDeps['rollup']) this.detectedStack.build.push('Rollup');
      if (allDeps['turbo']) this.detectedStack.build.push('Turborepo');

      // Check scripts for hints
      const scripts = pkg.scripts || {};
      const scriptStr = JSON.stringify(scripts).toLowerCase();

      if (scriptStr.includes('prisma')) this.detectedStack.backend.push('Prisma');
      if (scriptStr.includes('drizzle')) this.detectedStack.backend.push('Drizzle');
      if (scriptStr.includes('supabase')) this.detectedStack.database.push('Supabase');

    } catch (err) {
      // No package.json - not a Node project
    }
  }

  /**
   * Analyze requirements.txt for Python projects
   */
  async analyzeRequirementsTxt() {
    const pythonFiles = ['requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py'];

    for (const file of pythonFiles) {
      try {
        const content = await readFile(join(this.projectPath, file), 'utf-8');
        this.configFiles[file] = true;

        // Python frameworks
        if (/django/i.test(content)) this.detectedStack.backend.push('Django');
        if (/flask/i.test(content)) this.detectedStack.backend.push('Flask');
        if (/fastapi/i.test(content)) this.detectedStack.backend.push('FastAPI');
        if (/tornado/i.test(content)) this.detectedStack.backend.push('Tornado');
        if (/aiohttp/i.test(content)) this.detectedStack.backend.push('aiohttp');
        if (/starlette/i.test(content)) this.detectedStack.backend.push('Starlette');

        // Python ORMs
        if (/sqlalchemy/i.test(content)) this.detectedStack.backend.push('SQLAlchemy');
        if (/peewee/i.test(content)) this.detectedStack.backend.push('Peewee');
        if (/tortoise/i.test(content)) this.detectedStack.backend.push('Tortoise ORM');

        // Python databases
        if (/psycopg/i.test(content)) this.detectedStack.database.push('PostgreSQL');
        if (/pymongo/i.test(content)) this.detectedStack.database.push('MongoDB');
        if (/redis/i.test(content)) this.detectedStack.database.push('Redis');

        // Python auth
        if (/pyjwt/i.test(content)) this.detectedStack.auth.push('PyJWT');
        if (/passlib/i.test(content)) this.detectedStack.auth.push('Passlib');
        if (/python-jose/i.test(content)) this.detectedStack.auth.push('python-jose');

        // Python security
        if (/python-dotenv/i.test(content)) this.detectedStack.security.push('python-dotenv');

      } catch {
        // File doesn't exist
      }
    }
  }

  /**
   * Analyze configuration files
   */
  async analyzeConfigFiles() {
    const configChecks = [
      // Supabase
      { path: 'supabase/config.toml', tech: 'Supabase', category: 'database' },
      { path: '.supabase', tech: 'Supabase', category: 'database' },

      // Next.js
      { path: 'next.config.js', tech: 'Next.js', category: 'frontend' },
      { path: 'next.config.mjs', tech: 'Next.js', category: 'frontend' },
      { path: 'next.config.ts', tech: 'Next.js', category: 'frontend' },

      // Nuxt
      { path: 'nuxt.config.js', tech: 'Nuxt.js', category: 'frontend' },
      { path: 'nuxt.config.ts', tech: 'Nuxt.js', category: 'frontend' },

      // Angular
      { path: 'angular.json', tech: 'Angular', category: 'frontend' },

      // Svelte
      { path: 'svelte.config.js', tech: 'SvelteKit', category: 'frontend' },

      // Vue
      { path: 'vue.config.js', tech: 'Vue.js', category: 'frontend' },

      // Vite
      { path: 'vite.config.js', tech: 'Vite', category: 'build' },
      { path: 'vite.config.ts', tech: 'Vite', category: 'build' },

      // Prisma
      { path: 'prisma/schema.prisma', tech: 'Prisma', category: 'backend' },

      // Drizzle
      { path: 'drizzle.config.ts', tech: 'Drizzle', category: 'backend' },

      // Docker
      { path: 'Dockerfile', tech: 'Docker', category: 'cloud' },
      { path: 'docker-compose.yml', tech: 'Docker Compose', category: 'cloud' },
      { path: 'docker-compose.yaml', tech: 'Docker Compose', category: 'cloud' },

      // Vercel
      { path: 'vercel.json', tech: 'Vercel', category: 'cloud' },

      // Netlify
      { path: 'netlify.toml', tech: 'Netlify', category: 'cloud' },

      // Cloudflare
      { path: 'wrangler.toml', tech: 'Cloudflare Workers', category: 'cloud' },

      // Firebase
      { path: 'firebase.json', tech: 'Firebase', category: 'cloud' },
      { path: '.firebaserc', tech: 'Firebase', category: 'cloud' },

      // ESLint
      { path: '.eslintrc.js', tech: 'ESLint', category: 'build' },
      { path: '.eslintrc.json', tech: 'ESLint', category: 'build' },
      { path: 'eslint.config.js', tech: 'ESLint', category: 'build' },

      // TypeScript
      { path: 'tsconfig.json', tech: 'TypeScript', category: 'build' },

      // Tailwind
      { path: 'tailwind.config.js', tech: 'Tailwind CSS', category: 'frontend' },
      { path: 'tailwind.config.ts', tech: 'Tailwind CSS', category: 'frontend' },

      // NextAuth
      { path: 'auth.config.ts', tech: 'Auth.js', category: 'auth' },
      { path: 'auth.ts', tech: 'Auth.js', category: 'auth' },
    ];

    for (const check of configChecks) {
      try {
        await access(join(this.projectPath, check.path));
        this.configFiles[check.path] = true;
        if (!this.detectedStack[check.category].includes(check.tech)) {
          this.detectedStack[check.category].push(check.tech);
        }
      } catch {
        // File doesn't exist
      }
    }
  }

  /**
   * Analyze source code patterns
   */
  async analyzeSourceCode() {
    const sourceFiles = await this.getAllSourceFiles();

    for (const file of sourceFiles.slice(0, 100)) { // Sample first 100 files
      try {
        const content = await readFile(file, 'utf-8');

        // Detect Supabase usage
        if (/createClient.*supabase|@supabase\/supabase-js|supabase\.from\(/i.test(content)) {
          if (!this.detectedStack.database.includes('Supabase')) {
            this.detectedStack.database.push('Supabase');
          }
        }

        // Detect Firebase
        if (/initializeApp|getFirestore|getAuth.*firebase/i.test(content)) {
          if (!this.detectedStack.database.includes('Firebase')) {
            this.detectedStack.database.push('Firebase');
          }
        }

        // Detect MongoDB patterns
        if (/MongoClient|mongoose\.connect|\.findOne\(|\.insertMany\(/i.test(content)) {
          if (!this.detectedStack.database.includes('MongoDB')) {
            this.detectedStack.database.push('MongoDB');
          }
        }

        // Detect SQL patterns
        if (/SELECT\s+.*FROM|INSERT\s+INTO|CREATE\s+TABLE/i.test(content)) {
          this.sourcePatterns.rawSQL = true;
        }

        // Detect GraphQL
        if (/gql`|graphql`|type\s+Query\s*\{|type\s+Mutation/i.test(content)) {
          if (!this.detectedStack.api.includes('GraphQL')) {
            this.detectedStack.api.push('GraphQL');
          }
        }

        // Detect tRPC
        if (/createTRPCRouter|publicProcedure|protectedProcedure/i.test(content)) {
          if (!this.detectedStack.api.includes('tRPC')) {
            this.detectedStack.api.push('tRPC');
          }
        }

        // Detect REST API patterns
        if (/app\.(get|post|put|delete|patch)\s*\(|router\.(get|post|put|delete)/i.test(content)) {
          if (!this.detectedStack.api.includes('REST API')) {
            this.detectedStack.api.push('REST API');
          }
        }

      } catch {
        // Skip unreadable files
      }
    }
  }

  /**
   * Analyze Docker configuration
   */
  async analyzeDockerFiles() {
    try {
      const dockerfile = await readFile(join(this.projectPath, 'Dockerfile'), 'utf-8');

      // Detect base images
      if (/FROM\s+node/i.test(dockerfile)) this.detectedStack.other.push('Node.js runtime');
      if (/FROM\s+python/i.test(dockerfile)) this.detectedStack.other.push('Python runtime');
      if (/FROM\s+golang/i.test(dockerfile)) this.detectedStack.other.push('Go runtime');
      if (/FROM\s+ruby/i.test(dockerfile)) this.detectedStack.other.push('Ruby runtime');
      if (/FROM\s+nginx/i.test(dockerfile)) this.detectedStack.cloud.push('Nginx');
      if (/FROM\s+postgres/i.test(dockerfile)) this.detectedStack.database.push('PostgreSQL');
      if (/FROM\s+mongo/i.test(dockerfile)) this.detectedStack.database.push('MongoDB');
      if (/FROM\s+redis/i.test(dockerfile)) this.detectedStack.database.push('Redis');

    } catch {
      // No Dockerfile
    }
  }

  /**
   * Analyze CI/CD configuration
   */
  async analyzeCICD() {
    const ciChecks = [
      { path: '.github/workflows', tech: 'GitHub Actions', category: 'cloud' },
      { path: '.gitlab-ci.yml', tech: 'GitLab CI', category: 'cloud' },
      { path: '.circleci/config.yml', tech: 'CircleCI', category: 'cloud' },
      { path: 'Jenkinsfile', tech: 'Jenkins', category: 'cloud' },
      { path: '.travis.yml', tech: 'Travis CI', category: 'cloud' },
      { path: 'azure-pipelines.yml', tech: 'Azure Pipelines', category: 'cloud' },
    ];

    for (const check of ciChecks) {
      try {
        const stats = await stat(join(this.projectPath, check.path));
        if (stats.isDirectory() || stats.isFile()) {
          this.configFiles[check.path] = true;
          if (!this.detectedStack[check.category].includes(check.tech)) {
            this.detectedStack[check.category].push(check.tech);
          }
        }
      } catch {
        // Doesn't exist
      }
    }
  }

  /**
   * Analyze git history for tech patterns (lightweight)
   */
  async analyzeGitHistory() {
    // Check for common git-tracked config files
    try {
      const gitignore = await readFile(join(this.projectPath, '.gitignore'), 'utf-8');

      // Detect from gitignore patterns
      if (/\.env/i.test(gitignore)) this.sourcePatterns.hasEnvFiles = true;
      if (/node_modules/i.test(gitignore)) this.sourcePatterns.isNodeProject = true;
      if (/__pycache__|\.pyc/i.test(gitignore)) this.sourcePatterns.isPythonProject = true;
      if (/\.next/i.test(gitignore)) this.detectedStack.frontend.push('Next.js');
      if (/\.nuxt/i.test(gitignore)) this.detectedStack.frontend.push('Nuxt.js');

    } catch {
      // No .gitignore
    }
  }

  /**
   * Get all source files in project
   */
  async getAllSourceFiles(dir = this.projectPath, files = []) {
    const skipDirs = ['node_modules', '.git', 'dist', 'build', '.next', '__pycache__', 'venv', '.venv', 'vendor'];
    const sourceExts = ['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.go', '.php', '.java', '.vue', '.svelte'];

    try {
      const entries = await readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = join(dir, entry.name);

        if (entry.isDirectory() && !skipDirs.includes(entry.name)) {
          await this.getAllSourceFiles(fullPath, files);
        } else if (sourceExts.includes(extname(entry.name))) {
          files.push(fullPath);
        }
      }
    } catch {
      // Permission error or similar
    }

    return files;
  }

  /**
   * Calculate confidence scores
   */
  calculateConfidence() {
    for (const [category, techs] of Object.entries(this.detectedStack)) {
      for (const tech of techs) {
        let score = 0;

        // Package.json/requirements.txt detection = high confidence
        if (this.configFiles['package.json'] || this.configFiles['requirements.txt']) {
          score += 40;
        }

        // Config file detection = very high confidence
        const configFileCount = Object.keys(this.configFiles).filter(f =>
          f.toLowerCase().includes(tech.toLowerCase().split(' ')[0].split('.')[0])
        ).length;
        score += configFileCount * 30;

        // Source code detection = medium confidence
        score += 20;

        this.confidence[tech] = Math.min(100, score);
      }
    }
  }

  /**
   * Generate human-readable summary
   */
  generateSummary() {
    const parts = [];

    if (this.detectedStack.frontend.length) {
      parts.push(`Frontend: ${this.detectedStack.frontend.join(', ')}`);
    }
    if (this.detectedStack.backend.length) {
      parts.push(`Backend: ${this.detectedStack.backend.join(', ')}`);
    }
    if (this.detectedStack.database.length) {
      parts.push(`Database: ${this.detectedStack.database.join(', ')}`);
    }
    if (this.detectedStack.auth.length) {
      parts.push(`Auth: ${this.detectedStack.auth.join(', ')}`);
    }
    if (this.detectedStack.api.length) {
      parts.push(`API: ${this.detectedStack.api.join(', ')}`);
    }
    if (this.detectedStack.cloud.length) {
      parts.push(`Cloud/Deploy: ${this.detectedStack.cloud.join(', ')}`);
    }

    return {
      text: parts.join(' | '),
      totalTechnologies: Object.values(this.detectedStack).flat().length,
      categories: Object.keys(this.detectedStack).filter(k => this.detectedStack[k].length > 0)
    };
  }
}

export default StackDetector;
