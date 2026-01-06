# Check React Vulnerabilities

Scan this project's React ecosystem packages for known security vulnerabilities.

## Instructions

Check the React ecosystem dependencies for known CVEs and security issues:

1. **Packages to check**:
   - react, react-dom (core)
   - next (Next.js framework)
   - react-router, react-router-dom (routing)
   - @tanstack/react-query (data fetching)
   - @remix-run/react (Remix framework)
   - styled-components, @emotion/react (CSS-in-JS)
   - react-hook-form, formik (forms)
   - react-scripts (Create React App)

2. **Version comparison**:
   - Read package.json to get installed versions
   - Compare against known vulnerable versions
   - Check for deprecated/unmaintained packages

3. **Known critical issues to check**:
   - Next.js < 14.1.1: CVE-2024-34351 (SSRF in Server Actions)
   - Next.js < 13.5.1: CVE-2023-46298 (URL validation bypass)
   - react-dev-utils < 12.0.1: Command injection
   - react-scripts < 5.0.1: Multiple vulnerabilities

4. **Report format**:
   ```
   ## React Security Check Results

   ### Critical Vulnerabilities
   | Package | Installed | Fixed In | CVE |
   |---------|-----------|----------|-----|
   | next | 13.4.0 | 14.1.1 | CVE-2024-34351 |

   ### Recommendations
   - Update next: `npm install next@latest`
   - Review react-helmet usage (unmaintained)

   ### All Clear
   - [List packages with no known issues]
   ```

5. **Live database check**:
   If possible, also query OSV (osv.dev) for the latest vulnerability data to catch any 0-days not in local database.

Focus on providing actionable remediation - exact npm commands to fix issues.
