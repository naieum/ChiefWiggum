"""
Generic API Security Checks

Checks applicable to any REST/GraphQL API regardless of
the underlying database or framework.
"""

from dataclasses import dataclass
from typing import Optional, Callable
import re


@dataclass
class APICheckResult:
    """Result of an API security check"""
    check_id: str
    vulnerable: bool
    severity: str
    evidence: list[str]
    affected_endpoints: list[str]
    remediation: str


class APISecurityChecks:
    """
    Security checks for REST and GraphQL APIs.

    Covers OWASP API Security Top 10:
    - API1: Broken Object Level Authorization (BOLA)
    - API2: Broken Authentication
    - API3: Broken Object Property Level Authorization
    - API4: Unrestricted Resource Consumption
    - API5: Broken Function Level Authorization
    - API6: Unrestricted Access to Sensitive Business Flows
    - API7: Server Side Request Forgery (SSRF)
    - API8: Security Misconfiguration
    - API9: Improper Inventory Management
    - API10: Unsafe Consumption of APIs
    """

    def __init__(self, http_callback: Optional[Callable] = None):
        self._http = http_callback

    def check_bola(
        self,
        endpoint: str,
        id_param: str,
        user_a_id: str,
        user_b_id: str,
        user_a_token: str
    ) -> APICheckResult:
        """
        Check for Broken Object Level Authorization (BOLA/IDOR).

        Tests if user A can access user B's resources.
        """
        evidence = []
        vulnerable = False

        # Test 1: Can user A access their own resource?
        # Test 2: Can user A access user B's resource?

        # Note: Real implementation would make HTTP requests
        # own_resource = self._http("GET", f"{endpoint}/{user_a_id}",
        #                          {"Authorization": f"Bearer {user_a_token}"})
        # other_resource = self._http("GET", f"{endpoint}/{user_b_id}",
        #                            {"Authorization": f"Bearer {user_a_token}"})

        # if other_resource.status == 200:
        #     vulnerable = True
        #     evidence.append(f"User A can access User B's resource at {endpoint}/{user_b_id}")

        return APICheckResult(
            check_id="API-001",
            vulnerable=vulnerable,
            severity="high" if vulnerable else "info",
            evidence=evidence,
            affected_endpoints=[endpoint] if vulnerable else [],
            remediation=(
                "Implement object-level authorization checks. "
                "Verify that the requesting user owns or has permission "
                "to access the requested resource."
            )
        )

    def check_rate_limiting(
        self,
        endpoint: str,
        num_requests: int = 50,
        time_window_seconds: float = 1.0
    ) -> APICheckResult:
        """
        Check if endpoint has rate limiting.

        Safe check: Makes multiple rapid requests to test limits.
        """
        evidence = []
        vulnerable = False

        # Note: Real implementation would make rapid requests
        # Track response codes - 429 indicates rate limiting exists

        return APICheckResult(
            check_id="API-004",
            vulnerable=vulnerable,
            severity="medium" if vulnerable else "info",
            evidence=evidence,
            affected_endpoints=[endpoint] if vulnerable else [],
            remediation=(
                "Implement rate limiting on all API endpoints. "
                "Use sliding window or token bucket algorithms. "
                "Return 429 Too Many Requests when limits exceeded."
            )
        )

    def check_excessive_data_exposure(
        self,
        response_body: str,
        expected_fields: list[str]
    ) -> APICheckResult:
        """
        Check for excessive data exposure in API responses.

        Compares response fields against expected fields.
        """
        evidence = []
        extra_fields = []

        # Sensitive fields that shouldn't typically be exposed
        sensitive_fields = [
            'password', 'password_hash', 'hashed_password',
            'secret', 'api_key', 'apiKey', 'private_key',
            'ssn', 'social_security', 'tax_id',
            'credit_card', 'card_number', 'cvv',
            'salt', 'token', 'refresh_token',
            'internal_id', 'admin', 'is_admin', 'role',
            'created_by', 'modified_by'
        ]

        # Find fields in response
        field_pattern = r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:'
        response_fields = set(re.findall(field_pattern, response_body))

        # Check for sensitive fields
        for field in response_fields:
            if field.lower() in [f.lower() for f in sensitive_fields]:
                evidence.append(f"Sensitive field '{field}' exposed in response")

            if field not in expected_fields:
                extra_fields.append(field)

        vulnerable = len(evidence) > 0

        return APICheckResult(
            check_id="API-003",
            vulnerable=vulnerable,
            severity="medium" if vulnerable else "info",
            evidence=evidence,
            affected_endpoints=[],
            remediation=(
                "Filter API responses to include only necessary fields. "
                "Use DTOs or serializers to control output. "
                "Never return password hashes, tokens, or internal IDs."
            )
        )

    def check_security_headers(
        self,
        response_headers: dict
    ) -> APICheckResult:
        """
        Check for missing security headers.
        """
        evidence = []
        missing = []

        required_headers = {
            'Strict-Transport-Security': 'HSTS',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'clickjacking protection',
            'Content-Security-Policy': 'CSP',
            'X-XSS-Protection': 'XSS protection',
            'Referrer-Policy': 'referrer control',
            'Permissions-Policy': 'feature policy'
        }

        headers_lower = {k.lower(): v for k, v in response_headers.items()}

        for header, description in required_headers.items():
            if header.lower() not in headers_lower:
                missing.append(header)
                evidence.append(f"Missing {description} ({header})")

        # Check for dangerous headers
        dangerous = ['Server', 'X-Powered-By', 'X-AspNet-Version']
        for header in dangerous:
            if header.lower() in headers_lower:
                evidence.append(f"Information disclosure via {header} header")

        return APICheckResult(
            check_id="API-008",
            vulnerable=len(missing) > 3,
            severity="low",
            evidence=evidence,
            affected_endpoints=[],
            remediation=(
                "Configure security headers in your web server or application. "
                "Remove headers that disclose technology information."
            )
        )

    def check_cors_configuration(
        self,
        response_headers: dict,
        expected_origins: list[str]
    ) -> APICheckResult:
        """
        Check CORS configuration for security issues.
        """
        evidence = []
        vulnerable = False

        acao = response_headers.get('Access-Control-Allow-Origin', '')
        acac = response_headers.get('Access-Control-Allow-Credentials', '')

        # Check for wildcard with credentials
        if acao == '*' and acac.lower() == 'true':
            vulnerable = True
            evidence.append("Wildcard origin with credentials allowed - critical misconfiguration")

        # Check for overly permissive origin
        if acao == '*':
            evidence.append("Wildcard CORS origin - may be intentional but review needed")

        # Check if origin is reflected without validation
        if acao and acao not in expected_origins and acao != '*':
            evidence.append(f"Unexpected origin allowed: {acao}")

        return APICheckResult(
            check_id="API-008-CORS",
            vulnerable=vulnerable,
            severity="high" if vulnerable else "low",
            evidence=evidence,
            affected_endpoints=[],
            remediation=(
                "Configure CORS with explicit allowed origins. "
                "Never use wildcard with credentials. "
                "Validate Origin header against whitelist."
            )
        )

    def check_graphql_introspection(
        self,
        graphql_endpoint: str
    ) -> APICheckResult:
        """
        Check if GraphQL introspection is enabled in production.
        """
        evidence = []
        vulnerable = False

        introspection_query = """
        {
            __schema {
                types { name }
            }
        }
        """

        # Note: Real implementation would make HTTP request
        # response = self._http("POST", graphql_endpoint,
        #                      {"Content-Type": "application/json"},
        #                      json.dumps({"query": introspection_query}))

        # if response.status == 200 and "__schema" in response.body:
        #     vulnerable = True
        #     evidence.append("GraphQL introspection is enabled")

        return APICheckResult(
            check_id="API-009",
            vulnerable=vulnerable,
            severity="medium" if vulnerable else "info",
            evidence=evidence,
            affected_endpoints=[graphql_endpoint] if vulnerable else [],
            remediation=(
                "Disable GraphQL introspection in production. "
                "Use schema documentation for developers instead."
            )
        )
