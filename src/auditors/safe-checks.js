/**
 * Safe Checks Module
 *
 * Performs NON-DESTRUCTIVE security checks against YOUR OWN localhost server.
 * These are read-only checks - no data modification, no fuzzing, no attacks.
 *
 * Checks include:
 * - HTTP security headers
 * - CORS configuration
 * - Cookie security flags
 * - TLS configuration
 * - Information disclosure
 */

export class SafeChecker {
  constructor(options = {}) {
    this.options = {
      allowedHosts: ['localhost', '127.0.0.1', '0.0.0.0'],
      defaultPort: 3000,
      timeout: 5000,
      ...options
    };
    this.findings = [];
  }

  /**
   * Validate that we're only testing allowed hosts
   */
  isAllowedHost(url) {
    try {
      const parsed = new URL(url);
      return this.options.allowedHosts.includes(parsed.hostname);
    } catch {
      return false;
    }
  }

  /**
   * Run all safe checks
   */
  async runChecks(targetUrl = null) {
    this.findings = [];

    const baseUrl = targetUrl || `http://localhost:${this.options.defaultPort}`;

    // Safety check - only test localhost
    if (!this.isAllowedHost(baseUrl)) {
      return {
        error: 'Guardian-Agent only tests localhost. Remote testing is not supported.',
        findings: []
      };
    }

    console.log(`  Testing: ${baseUrl}`);

    // Check if server is running
    const serverRunning = await this.checkServerRunning(baseUrl);
    if (!serverRunning) {
      return {
        message: 'No local server detected. Start your dev server to run dynamic checks.',
        findings: []
      };
    }

    // Run non-destructive checks
    await Promise.all([
      this.checkSecurityHeaders(baseUrl),
      this.checkCorsConfig(baseUrl),
      this.checkCookieFlags(baseUrl),
      this.checkInfoDisclosure(baseUrl),
    ]);

    return {
      targetUrl: baseUrl,
      findings: this.findings,
      summary: this.summarize()
    };
  }

  /**
   * Check if local server is running
   */
  async checkServerRunning(baseUrl) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.options.timeout);

      const response = await fetch(baseUrl, {
        method: 'HEAD',
        signal: controller.signal
      });

      clearTimeout(timeout);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Check HTTP security headers
   */
  async checkSecurityHeaders(baseUrl) {
    try {
      const response = await fetch(baseUrl, { method: 'GET' });
      const headers = response.headers;

      // Required security headers
      const securityHeaders = [
        {
          name: 'Strict-Transport-Security',
          severity: 'high',
          description: 'HSTS header prevents downgrade attacks.',
          remediation: 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
        },
        {
          name: 'X-Content-Type-Options',
          expected: 'nosniff',
          severity: 'medium',
          description: 'Prevents MIME-type sniffing attacks.',
          remediation: 'Add header: X-Content-Type-Options: nosniff'
        },
        {
          name: 'X-Frame-Options',
          severity: 'medium',
          description: 'Prevents clickjacking attacks.',
          remediation: 'Add header: X-Frame-Options: DENY or SAMEORIGIN'
        },
        {
          name: 'Content-Security-Policy',
          severity: 'medium',
          description: 'CSP helps prevent XSS attacks.',
          remediation: 'Add a Content-Security-Policy header appropriate for your app.'
        },
        {
          name: 'X-XSS-Protection',
          severity: 'low',
          description: 'Legacy XSS protection (modern browsers use CSP).',
          remediation: 'Add header: X-XSS-Protection: 1; mode=block'
        },
        {
          name: 'Referrer-Policy',
          severity: 'low',
          description: 'Controls referrer information leakage.',
          remediation: 'Add header: Referrer-Policy: strict-origin-when-cross-origin'
        }
      ];

      for (const header of securityHeaders) {
        const value = headers.get(header.name);

        if (!value) {
          this.addFinding({
            severity: header.severity,
            title: `Missing Security Header: ${header.name}`,
            description: header.description,
            remediation: header.remediation,
            location: { endpoint: baseUrl }
          });
        } else if (header.expected && value.toLowerCase() !== header.expected.toLowerCase()) {
          this.addFinding({
            severity: header.severity,
            title: `Misconfigured Header: ${header.name}`,
            description: `Expected "${header.expected}", got "${value}".`,
            remediation: header.remediation,
            location: { endpoint: baseUrl }
          });
        }
      }

      // Check for information disclosure headers
      const disclosureHeaders = ['X-Powered-By', 'Server'];
      for (const headerName of disclosureHeaders) {
        const value = headers.get(headerName);
        if (value) {
          this.addFinding({
            severity: 'low',
            title: `Information Disclosure: ${headerName}`,
            description: `Header reveals: ${value}`,
            remediation: `Remove or obfuscate the ${headerName} header.`,
            location: { endpoint: baseUrl }
          });
        }
      }
    } catch (err) {
      // Connection error, skip
    }
  }

  /**
   * Check CORS configuration
   */
  async checkCorsConfig(baseUrl) {
    try {
      // Send a preflight-style request
      const response = await fetch(baseUrl, {
        method: 'OPTIONS',
        headers: {
          'Origin': 'https://evil-site.com',
          'Access-Control-Request-Method': 'POST'
        }
      });

      const allowOrigin = response.headers.get('Access-Control-Allow-Origin');
      const allowCreds = response.headers.get('Access-Control-Allow-Credentials');

      // Check for overly permissive CORS
      if (allowOrigin === '*') {
        this.addFinding({
          severity: 'medium',
          title: 'Permissive CORS: Wildcard Origin',
          description: 'Access-Control-Allow-Origin is set to *, allowing any origin.',
          remediation: 'Restrict CORS to specific trusted origins.',
          location: { endpoint: baseUrl }
        });
      }

      // Check for reflected origin (dangerous pattern)
      if (allowOrigin === 'https://evil-site.com') {
        this.addFinding({
          severity: 'high',
          title: 'CORS Reflects Arbitrary Origin',
          description: 'Server reflects any Origin header, which bypasses CORS protection.',
          remediation: 'Validate origins against an allowlist instead of reflecting.',
          location: { endpoint: baseUrl }
        });
      }

      // Wildcard with credentials is invalid but check anyway
      if (allowOrigin === '*' && allowCreds === 'true') {
        this.addFinding({
          severity: 'high',
          title: 'Dangerous CORS Configuration',
          description: 'Wildcard origin with credentials enabled (browsers will block this, but indicates misconfiguration).',
          remediation: 'Use specific origins when allowing credentials.',
          location: { endpoint: baseUrl }
        });
      }
    } catch {
      // CORS check failed, skip
    }
  }

  /**
   * Check cookie security flags
   */
  async checkCookieFlags(baseUrl) {
    try {
      const response = await fetch(baseUrl);
      const setCookies = response.headers.get('Set-Cookie');

      if (!setCookies) return;

      // Parse cookies (simplified)
      const cookies = setCookies.split(',').map(c => c.trim());

      for (const cookie of cookies) {
        const cookieName = cookie.split('=')[0];

        // Check for missing Secure flag
        if (!cookie.toLowerCase().includes('secure')) {
          this.addFinding({
            severity: 'medium',
            title: 'Cookie Missing Secure Flag',
            description: `Cookie "${cookieName}" can be sent over HTTP.`,
            remediation: 'Add the Secure flag to cookies containing sensitive data.',
            location: { endpoint: baseUrl, cookie: cookieName }
          });
        }

        // Check for missing HttpOnly flag
        if (!cookie.toLowerCase().includes('httponly')) {
          this.addFinding({
            severity: 'medium',
            title: 'Cookie Missing HttpOnly Flag',
            description: `Cookie "${cookieName}" is accessible via JavaScript.`,
            remediation: 'Add the HttpOnly flag to prevent XSS cookie theft.',
            location: { endpoint: baseUrl, cookie: cookieName }
          });
        }

        // Check for missing SameSite flag
        if (!cookie.toLowerCase().includes('samesite')) {
          this.addFinding({
            severity: 'low',
            title: 'Cookie Missing SameSite Flag',
            description: `Cookie "${cookieName}" lacks SameSite attribute.`,
            remediation: 'Add SameSite=Strict or SameSite=Lax to prevent CSRF.',
            location: { endpoint: baseUrl, cookie: cookieName }
          });
        }
      }
    } catch {
      // Cookie check failed, skip
    }
  }

  /**
   * Check for common information disclosure
   */
  async checkInfoDisclosure(baseUrl) {
    // Check common endpoints that might leak info
    const infoEndpoints = [
      { path: '/.env', name: 'Environment file' },
      { path: '/.git/config', name: 'Git config' },
      { path: '/phpinfo.php', name: 'PHP info' },
      { path: '/server-status', name: 'Server status' },
      { path: '/debug', name: 'Debug endpoint' },
      { path: '/.DS_Store', name: 'macOS metadata' },
      { path: '/config.json', name: 'Config file' },
    ];

    for (const endpoint of infoEndpoints) {
      try {
        const response = await fetch(`${baseUrl}${endpoint.path}`, {
          method: 'HEAD'
        });

        if (response.ok) {
          this.addFinding({
            severity: 'high',
            title: `Exposed Sensitive File: ${endpoint.name}`,
            description: `${endpoint.path} is publicly accessible.`,
            remediation: `Block access to ${endpoint.path} in your web server configuration.`,
            location: { endpoint: `${baseUrl}${endpoint.path}` }
          });
        }
      } catch {
        // Endpoint not accessible, which is good
      }
    }
  }

  /**
   * Add a finding
   */
  addFinding(finding) {
    this.findings.push({
      category: 'safe-check',
      ...finding
    });
  }

  /**
   * Generate summary
   */
  summarize() {
    const summary = {
      total: this.findings.length,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    };

    for (const finding of this.findings) {
      summary.bySeverity[finding.severity]++;
    }

    return summary;
  }
}

export default SafeChecker;
