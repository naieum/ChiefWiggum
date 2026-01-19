# Security Fix TDD

Test-Driven Development workflow for security vulnerabilities.

## When to Use This Skill

Use this skill when:
- Fixing a vulnerability found by Guardian-Agent
- Implementing security controls (rate limiting, validation, etc.)
- Patching a CVE in your code
- Adding authentication or authorization

## The RED-GREEN-REFACTOR Security Cycle

### RED: Write a Failing Security Test

First, prove the vulnerability exists with a test:

```javascript
// Example: Testing for SQL injection vulnerability
describe('Security: SQL Injection', () => {
  it('should be vulnerable to SQL injection (RED - expected to fail after fix)', async () => {
    const maliciousInput = "'; DROP TABLE users; --";

    // This test documents the vulnerability
    // After fix, this attack should be neutralized
    const response = await request(app)
      .get(`/api/users?search=${maliciousInput}`)
      .expect(200);

    // If vulnerable: query executes, might error or return unexpected data
    // If fixed: input is sanitized, returns empty or error safely
  });

  it('should sanitize user input in search queries', async () => {
    const maliciousInput = "'; DROP TABLE users; --";

    const response = await request(app)
      .get(`/api/users?search=${encodeURIComponent(maliciousInput)}`)
      .expect(200);

    // Should treat input as literal string, not SQL
    expect(response.body.users).toEqual([]);
    // Database should still be intact
    const users = await db.query('SELECT COUNT(*) FROM users');
    expect(users.count).toBeGreaterThan(0);
  });
});
```

### Security Test Patterns

**XSS Prevention Test:**
```javascript
it('should escape HTML in user-generated content', () => {
  const maliciousInput = '<script>alert("xss")</script>';
  const rendered = renderUserContent(maliciousInput);

  expect(rendered).not.toContain('<script>');
  expect(rendered).toContain('&lt;script&gt;');
});
```

**Authentication Bypass Test:**
```javascript
it('should reject requests without valid authentication', async () => {
  const response = await request(app)
    .get('/api/admin/users')
    .set('Authorization', 'Bearer invalid-token')
    .expect(401);

  expect(response.body.error).toBe('Invalid token');
});
```

**Rate Limiting Test:**
```javascript
it('should rate limit after 100 requests per minute', async () => {
  // Make 100 requests (should succeed)
  for (let i = 0; i < 100; i++) {
    await request(app).get('/api/endpoint').expect(200);
  }

  // 101st request should be rate limited
  const response = await request(app)
    .get('/api/endpoint')
    .expect(429);

  expect(response.body.error).toContain('rate limit');
});
```

**Secret Exposure Test:**
```javascript
it('should not expose sensitive data in error responses', async () => {
  const response = await request(app)
    .get('/api/users/invalid-id')
    .expect(404);

  const responseText = JSON.stringify(response.body);

  // Should not contain stack traces or internal details
  expect(responseText).not.toMatch(/at\s+\w+\s+\(/); // stack trace
  expect(responseText).not.toContain('password');
  expect(responseText).not.toContain('secret');
  expect(responseText).not.toContain(process.env.DATABASE_URL);
});
```

### GREEN: Implement the Fix

Apply the minimal fix to make the test pass:

```javascript
// BEFORE (vulnerable):
app.get('/api/users', (req, res) => {
  const query = `SELECT * FROM users WHERE name LIKE '%${req.query.search}%'`;
  db.query(query).then(users => res.json({ users }));
});

// AFTER (fixed):
app.get('/api/users', (req, res) => {
  const query = 'SELECT * FROM users WHERE name LIKE $1';
  const searchPattern = `%${req.query.search}%`;
  db.query(query, [searchPattern]).then(users => res.json({ users }));
});
```

### REFACTOR: Improve Without Breaking

Once tests pass, improve the code:

```javascript
// REFACTORED: Extract to reusable utility
import { sanitizeSearchInput } from '../utils/security';
import { searchUsers } from '../services/users';

app.get('/api/users', async (req, res) => {
  const searchTerm = sanitizeSearchInput(req.query.search);
  const users = await searchUsers(searchTerm);
  res.json({ users });
});
```

## Security Test Checklist

For each vulnerability type, ensure tests cover:

### Injection (SQLi, NoSQLi, Command)
- [ ] Malicious input is sanitized
- [ ] Parameterized queries are used
- [ ] Error messages don't leak query structure

### XSS
- [ ] User input is escaped in HTML context
- [ ] User input is escaped in JavaScript context
- [ ] Content-Security-Policy is set

### Authentication
- [ ] Invalid credentials are rejected
- [ ] Tokens expire appropriately
- [ ] Session fixation is prevented

### Authorization
- [ ] Users can't access other users' data
- [ ] Role checks are enforced
- [ ] Privilege escalation is prevented

### Secrets
- [ ] No secrets in responses
- [ ] No secrets in logs
- [ ] No secrets in error messages

## Integration with Guardian-Agent

After fixing, re-run the relevant scan:

```
1. Fix the vulnerability using TDD
2. Run `scan_project_security` to verify fix
3. Run `security_score` to see improvement
4. Commit with descriptive message
```

## Commit Message Format

```
fix(security): prevent SQL injection in user search

- Use parameterized queries instead of string concatenation
- Add input validation for search parameter
- Add security regression test

Fixes: GUARDIAN-SQL-001
Severity: High
```
