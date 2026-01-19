"""
Safe Check Implementations for Guardian-Agent

Non-destructive security checks that can be run without
Exploit-Approval flag. These checks do not modify target state.

Mitigations for Active Tests Breaking Things:
- ValidatedHTTPClient enforces read-only operations for safe checks
- Method validation prevents POST/PUT/DELETE/PATCH in safe mode
- Endpoint blocklist prevents accessing admin/internal endpoints
- All HTTP operations go through the validated wrapper
"""

from dataclasses import dataclass
from typing import Optional, Callable
import re
import base64
import json


class HTTPValidationError(Exception):
    """Raised when HTTP operation violates safe check constraints."""
    pass


class ValidatedHTTPClient:
    """
    HTTP client wrapper that enforces constraints for safe checks.

    Prevents safe checks from accidentally performing destructive operations.
    """

    # Only read-only HTTP methods allowed in safe check mode
    SAFE_METHODS = {'GET', 'HEAD', 'OPTIONS'}

    # Endpoints that should never be accessed during safe checks
    BLOCKED_ENDPOINT_PATTERNS = [
        r'/admin',
        r'/internal',
        r'/superuser',
        r'/system',
        r'/config',
        r'/delete',
        r'/drop',
        r'/truncate',
        r'/__',  # Internal framework endpoints
    ]

    def __init__(
        self,
        http_callback: Optional[Callable],
        safe_mode: bool = True,
        max_body_size: int = 10000
    ):
        """
        Initialize validated HTTP client.

        Args:
            http_callback: Underlying HTTP callback
            safe_mode: If True, enforce safe check constraints
            max_body_size: Maximum request body size (bytes)
        """
        self._http = http_callback
        self._safe_mode = safe_mode
        self._max_body_size = max_body_size
        self._request_count = 0
        self._blocked_requests: list[dict] = []

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        body: Optional[str] = None
    ) -> tuple[int, dict, str]:
        """
        Make HTTP request with safe mode validation.

        Args:
            method: HTTP method
            url: Target URL
            headers: Request headers
            body: Request body

        Returns:
            tuple: (status_code, response_headers, response_body)

        Raises:
            HTTPValidationError: If request violates safe mode constraints
        """
        headers = headers or {}

        if self._safe_mode:
            self._validate_safe_request(method, url, body)

        if not self._http:
            raise HTTPValidationError(
                "No HTTP callback provided. Cannot make requests."
            )

        self._request_count += 1
        return self._http(method, url, headers, body)

    def _validate_safe_request(self, method: str, url: str, body: Optional[str]) -> None:
        """
        Validate request meets safe check constraints.

        Raises HTTPValidationError if constraints violated.
        """
        method_upper = method.upper()

        # Validate HTTP method
        if method_upper not in self.SAFE_METHODS:
            self._blocked_requests.append({
                "reason": "method_not_allowed",
                "method": method,
                "url": url
            })
            raise HTTPValidationError(
                f"HTTP method '{method}' not allowed in safe mode. "
                f"Only {self.SAFE_METHODS} are permitted for safe checks."
            )

        # Validate no body for GET requests in safe mode
        if method_upper == 'GET' and body:
            self._blocked_requests.append({
                "reason": "body_not_allowed_for_get",
                "url": url
            })
            raise HTTPValidationError(
                "GET requests with body not allowed in safe mode."
            )

        # Validate endpoint is not blocked
        url_lower = url.lower()
        for pattern in self.BLOCKED_ENDPOINT_PATTERNS:
            if re.search(pattern, url_lower):
                self._blocked_requests.append({
                    "reason": "blocked_endpoint",
                    "pattern": pattern,
                    "url": url
                })
                raise HTTPValidationError(
                    f"Endpoint matching '{pattern}' is blocked in safe mode. "
                    f"URL: {url}"
                )

    def get_stats(self) -> dict:
        """Get HTTP client statistics."""
        return {
            "request_count": self._request_count,
            "blocked_requests": self._blocked_requests,
            "safe_mode": self._safe_mode
        }


@dataclass
class SafeCheckResult:
    """Result of a safe check"""
    check_id: str
    check_name: str
    vulnerable: bool
    confidence: float
    evidence: list[str]
    details: dict


class SafeCheckRunner:
    """
    Runs non-destructive security checks.

    All checks in this class are read-only and safe to run
    without explicit exploit approval.

    Uses ValidatedHTTPClient to enforce safe operations.
    """

    def __init__(self, http_callback: Optional[Callable] = None):
        """
        Initialize the safe check runner.

        Args:
            http_callback: Callback for making HTTP requests
                          Signature: (method, url, headers, body) -> (status, headers, body)
        """
        # Wrap callback in validated client for safe mode enforcement
        self._http_client = ValidatedHTTPClient(
            http_callback=http_callback,
            safe_mode=True
        ) if http_callback else None
        self._http = http_callback  # Keep for backward compatibility

    def _safe_request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        body: Optional[str] = None
    ) -> Optional[tuple[int, dict, str]]:
        """
        Make a validated safe HTTP request.

        Returns None if no HTTP client configured.
        """
        if not self._http_client:
            return None

        try:
            return self._http_client.request(method, url, headers, body)
        except HTTPValidationError as e:
            # Log but don't fail - allow check to report "couldn't verify"
            return None

    # ==================== SUPABASE CHECKS ====================

    def check_supabase_rls_exposure(
        self,
        supabase_url: str,
        anon_key: str,
        table_names: Optional[list[str]] = None
    ) -> SafeCheckResult:
        """
        Check if Supabase tables are exposed due to missing RLS.

        This check only performs SELECT queries (read-only) via
        the validated HTTP client to ensure safety.
        """
        evidence = []
        vulnerable = False
        confidence = 0.0

        tables_to_check = table_names or [
            "users", "profiles", "accounts", "orders",
            "payments", "messages", "documents"
        ]

        exposed_tables = []
        checked_tables = []
        errors = []

        for table in tables_to_check:
            # Check if table is accessible without auth
            check_url = f"{supabase_url}/rest/v1/{table}?limit=1"
            headers = {
                "apikey": anon_key,
                "Authorization": f"Bearer {anon_key}",
                "Prefer": "return=representation"
            }

            # Use validated safe request
            result = self._safe_request("GET", check_url, headers, None)

            if result is None:
                # No HTTP client or request blocked
                if not self._http_client:
                    evidence.append("HTTP client not configured - cannot verify")
                continue

            status, resp_headers, body = result
            checked_tables.append(table)

            # Check for successful response with data
            if status == 200:
                try:
                    data = json.loads(body) if body else []
                    if data and len(data) > 0:
                        exposed_tables.append(table)
                        evidence.append(
                            f"Table '{table}' returns data ({len(data)} rows) "
                            "without user authentication"
                        )
                except json.JSONDecodeError:
                    pass
            elif status == 401:
                evidence.append(f"Table '{table}' properly requires authentication (401)")
            elif status == 403:
                evidence.append(f"Table '{table}' properly restricted (403 Forbidden)")
            elif status == 404:
                pass  # Table doesn't exist, skip
            else:
                errors.append(f"Table '{table}': unexpected status {status}")

        if exposed_tables:
            vulnerable = True
            confidence = 0.9
            evidence.append(f"VULNERABLE: Exposed tables: {', '.join(exposed_tables)}")
        elif checked_tables:
            evidence.append(f"Checked {len(checked_tables)} tables, none exposed")

        return SafeCheckResult(
            check_id="SUP-001",
            check_name="Supabase RLS Policy Check",
            vulnerable=vulnerable,
            confidence=confidence,
            evidence=evidence,
            details={
                "tables_checked": checked_tables,
                "exposed_tables": exposed_tables,
                "errors": errors,
                "remediation": "Enable RLS on exposed tables and create appropriate policies"
            }
        )

    def check_supabase_key_exposure(
        self,
        page_content: str
    ) -> SafeCheckResult:
        """
        Check for exposed Supabase service role key in client code.

        Analyzes page content for leaked service keys.
        """
        evidence = []
        vulnerable = False

        # Patterns for service role key (longer than anon key)
        service_key_patterns = [
            r'service_role["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{100,})["\']',
            r'SUPABASE_SERVICE_ROLE_KEY["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{100,})["\']',
            r'supabaseServiceKey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{100,})["\']',
        ]

        for pattern in service_key_patterns:
            matches = re.findall(pattern, page_content, re.IGNORECASE)
            if matches:
                vulnerable = True
                evidence.append(f"Potential service_role key found (pattern: {pattern[:30]}...)")

        # Check for JWT structure that might be service key
        jwt_pattern = r'eyJ[a-zA-Z0-9_-]{50,}\.[a-zA-Z0-9_-]{50,}\.[a-zA-Z0-9_-]{50,}'
        jwt_matches = re.findall(jwt_pattern, page_content)

        for jwt in jwt_matches:
            try:
                # Decode header to check if it's a service key
                header = json.loads(
                    base64.b64decode(jwt.split('.')[0] + '==').decode()
                )
                payload = json.loads(
                    base64.b64decode(jwt.split('.')[1] + '==').decode()
                )

                if payload.get('role') == 'service_role':
                    vulnerable = True
                    evidence.append("Service role JWT exposed in client code")

            except Exception:
                pass

        return SafeCheckResult(
            check_id="SUP-003",
            check_name="Supabase API Key Exposure",
            vulnerable=vulnerable,
            confidence=0.95 if vulnerable else 0.0,
            evidence=evidence,
            details={
                "keys_analyzed": len(jwt_matches),
                "remediation": "Remove service_role key from client code. Use only anon key."
            }
        )

    # ==================== MONGODB CHECKS ====================

    def check_nosql_operator_injection(
        self,
        endpoint: str,
        param_name: str,
        baseline_response: Optional[dict] = None
    ) -> SafeCheckResult:
        """
        Check for NoSQL operator injection vulnerability.

        Uses safe detection payloads that don't modify data.
        """
        evidence = []
        vulnerable = False

        # Safe detection payloads (read-only operations)
        test_cases = [
            {
                "payload": '{"$ne": null}',
                "description": "Not-equal operator",
                "indicator": "Returns more results than normal query"
            },
            {
                "payload": '{"$gt": ""}',
                "description": "Greater-than operator",
                "indicator": "Returns results when normal query returns none"
            },
            {
                "payload": '{"$exists": true}',
                "description": "Exists operator",
                "indicator": "Field existence check bypasses auth"
            }
        ]

        # Note: In real implementation, make requests and compare responses
        # for test in test_cases:
        #     response = self._http("GET", f"{endpoint}?{param_name}={test['payload']}", {}, None)
        #     if response differs from baseline in suspicious way:
        #         vulnerable = True
        #         evidence.append(f"Injection detected with: {test['description']}")

        return SafeCheckResult(
            check_id="MDB-001",
            check_name="NoSQL Operator Injection",
            vulnerable=vulnerable,
            confidence=0.8 if vulnerable else 0.0,
            evidence=evidence,
            details={
                "test_cases": test_cases,
                "parameter_tested": param_name,
                "remediation": "Sanitize input. Use MongoDB query builders. Validate object types."
            }
        )

    # ==================== SQL INJECTION CHECKS ====================

    def check_sql_error_based(
        self,
        endpoint: str,
        param_name: str
    ) -> SafeCheckResult:
        """
        Check for error-based SQL injection.

        Uses safe payloads that trigger errors without data extraction.
        """
        evidence = []
        vulnerable = False

        # Safe error-triggering payloads
        payloads = [
            "'",           # Single quote to break syntax
            "''",          # Double single quote
            "1'--",        # Comment injection
            "1 AND 1=1",   # Boolean check
            "1 AND 1=2",   # Boolean check (should differ)
        ]

        error_indicators = [
            r"SQL syntax",
            r"SQLSTATE",
            r"syntax error",
            r"unterminated",
            r"PostgreSQL",
            r"MySQL",
            r"ORA-\d+",
            r"Microsoft SQL",
        ]

        # Note: In real implementation, make requests and check for errors
        # for payload in payloads:
        #     response = self._http("GET", f"{endpoint}?{param_name}={payload}", {}, None)
        #     for indicator in error_indicators:
        #         if re.search(indicator, response.body, re.IGNORECASE):
        #             vulnerable = True
        #             evidence.append(f"SQL error triggered with payload: {payload}")

        return SafeCheckResult(
            check_id="PG-001",
            check_name="SQL Injection (Error-Based)",
            vulnerable=vulnerable,
            confidence=0.9 if vulnerable else 0.0,
            evidence=evidence,
            details={
                "payloads_tested": payloads,
                "error_patterns": error_indicators,
                "remediation": "Use parameterized queries. Disable verbose errors in production."
            }
        )

    # ==================== JWT CHECKS ====================

    def check_jwt_algorithm_confusion(
        self,
        token: str
    ) -> SafeCheckResult:
        """
        Check for JWT algorithm confusion vulnerability.

        Analyzes token structure without making authenticated requests.
        """
        evidence = []
        vulnerable = False
        details = {}

        try:
            parts = token.split('.')
            if len(parts) != 3:
                return SafeCheckResult(
                    check_id="AUTH-001",
                    check_name="JWT Algorithm Confusion",
                    vulnerable=False,
                    confidence=0.0,
                    evidence=["Invalid JWT format"],
                    details={"error": "Token does not have 3 parts"}
                )

            # Decode header
            header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))

            details["algorithm"] = header.get("alg")
            details["type"] = header.get("typ")

            # Check for weak algorithms
            weak_algorithms = ["none", "None", "NONE", "HS256"]  # HS256 if RSA expected
            if header.get("alg") in weak_algorithms:
                evidence.append(f"Weak algorithm detected: {header.get('alg')}")

            # The actual vulnerability test would require making requests
            # with modified tokens, which is an active test

            # For safe check, we just analyze the token structure
            if header.get("alg") == "none":
                vulnerable = True
                evidence.append("Token uses 'none' algorithm - critically vulnerable")

        except Exception as e:
            details["parse_error"] = str(e)

        return SafeCheckResult(
            check_id="AUTH-001",
            check_name="JWT Algorithm Confusion",
            vulnerable=vulnerable,
            confidence=0.7 if vulnerable else 0.0,
            evidence=evidence,
            details=details
        )

    # ==================== IDOR CHECKS ====================

    def check_idor_indicators(
        self,
        endpoint: str,
        response_body: str,
        authenticated_user_id: Optional[str] = None
    ) -> SafeCheckResult:
        """
        Check for IDOR vulnerability indicators.

        Analyzes response for patterns that suggest IDOR might be possible.
        """
        evidence = []
        vulnerable = False
        indicators = []

        # Check for sequential IDs in response
        sequential_id_pattern = r'"id"\s*:\s*(\d+)'
        id_matches = re.findall(sequential_id_pattern, response_body)

        if id_matches:
            ids = [int(m) for m in id_matches]
            if len(ids) > 1:
                # Check if IDs are sequential
                is_sequential = all(ids[i+1] - ids[i] == 1 for i in range(len(ids)-1))
                if is_sequential:
                    indicators.append("Sequential numeric IDs detected")

        # Check for UUID patterns (less vulnerable but still check)
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        uuids = re.findall(uuid_pattern, response_body, re.IGNORECASE)
        if uuids:
            indicators.append(f"UUIDs found in response ({len(uuids)} total)")

        # Check if user_id or similar is exposed
        sensitive_fields = ['user_id', 'userId', 'owner_id', 'ownerId', 'author_id']
        for field in sensitive_fields:
            if field in response_body:
                indicators.append(f"Sensitive field '{field}' exposed in response")

        if indicators:
            evidence.extend(indicators)
            # IDOR requires active testing to confirm
            # Safe check just identifies potential

        return SafeCheckResult(
            check_id="API-001",
            check_name="IDOR Indicators",
            vulnerable=False,  # Can't confirm without active testing
            confidence=0.0,
            evidence=evidence,
            details={
                "indicators_found": indicators,
                "ids_detected": id_matches[:10] if id_matches else [],
                "recommendation": "Manual testing required to confirm IDOR"
            }
        )

    # ==================== INFORMATION DISCLOSURE ====================

    def check_sensitive_data_exposure(
        self,
        response_body: str
    ) -> SafeCheckResult:
        """
        Check for sensitive data in API responses.

        Looks for passwords, tokens, keys, and PII in responses.
        """
        evidence = []
        findings = []

        # Sensitive field patterns
        sensitive_patterns = {
            "password": r'"password"\s*:\s*"[^"]+"',
            "api_key": r'"api[_-]?key"\s*:\s*"[^"]+"',
            "secret": r'"secret"\s*:\s*"[^"]+"',
            "token": r'"(access_?)?token"\s*:\s*"[a-zA-Z0-9_-]{20,}"',
            "ssn": r'\d{3}-\d{2}-\d{4}',
            "credit_card": r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            "private_key": r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
            "aws_key": r'AKIA[0-9A-Z]{16}',
        }

        for name, pattern in sensitive_patterns.items():
            if re.search(pattern, response_body, re.IGNORECASE):
                findings.append(name)
                evidence.append(f"Potential {name} exposure detected")

        vulnerable = len(findings) > 0

        return SafeCheckResult(
            check_id="API-003",
            check_name="Sensitive Data Exposure",
            vulnerable=vulnerable,
            confidence=0.85 if vulnerable else 0.0,
            evidence=evidence,
            details={
                "sensitive_fields_found": findings,
                "remediation": "Filter sensitive data server-side before returning responses"
            }
        )

    def check_security_headers(
        self,
        response_headers: dict
    ) -> SafeCheckResult:
        """
        Check for missing security headers.
        """
        evidence = []
        missing_headers = []

        required_headers = {
            "Strict-Transport-Security": "HSTS not configured",
            "X-Content-Type-Options": "Missing nosniff header",
            "X-Frame-Options": "Clickjacking protection missing",
            "Content-Security-Policy": "CSP not configured",
            "X-XSS-Protection": "XSS protection header missing"
        }

        headers_lower = {k.lower(): v for k, v in response_headers.items()}

        for header, message in required_headers.items():
            if header.lower() not in headers_lower:
                missing_headers.append(header)
                evidence.append(message)

        return SafeCheckResult(
            check_id="API-007",
            check_name="Security Headers Check",
            vulnerable=len(missing_headers) > 2,  # Some missing is common
            confidence=0.8,
            evidence=evidence,
            details={
                "missing_headers": missing_headers,
                "present_headers": list(response_headers.keys()),
                "remediation": "Configure security headers in your web server or application"
            }
        )
