"""
Phase 2: Discovery

Directory brute-forcing and API endpoint mapping.
Identifies attack surface by discovering hidden endpoints, API routes,
and potential entry points.

IMPORTANT: Rate limiting is enforced to prevent DoS conditions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable
import re
import time
from ..authorization import AuthorizationManager, TestingPhase


class EndpointType(Enum):
    """Types of discovered endpoints"""
    API = "api"
    ADMIN = "admin"
    AUTH = "auth"
    STATIC = "static"
    DEBUG = "debug"
    DOCUMENTATION = "documentation"
    HEALTH = "health"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


class HTTPMethod(Enum):
    """HTTP methods to test"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


@dataclass
class DiscoveredEndpoint:
    """Represents a discovered endpoint"""
    url: str
    method: HTTPMethod
    endpoint_type: EndpointType
    status_code: Optional[int] = None
    response_size: Optional[int] = None
    response_time_ms: Optional[float] = None
    requires_auth: bool = False
    parameters: list[str] = field(default_factory=list)
    headers_of_interest: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method.value,
            "type": self.endpoint_type.value,
            "status_code": self.status_code,
            "response_size": self.response_size,
            "response_time_ms": self.response_time_ms,
            "requires_auth": self.requires_auth,
            "parameters": self.parameters,
            "notes": self.notes
        }


@dataclass
class DiscoveryResults:
    """Results from discovery phase"""
    target: str
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    wordlist_used: str = ""
    total_requests: int = 0
    successful_discoveries: int = 0
    rate_limited: bool = False
    duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "endpoints": [ep.to_dict() for ep in self.endpoints],
            "wordlist_used": self.wordlist_used,
            "total_requests": self.total_requests,
            "successful_discoveries": self.successful_discoveries,
            "rate_limited": self.rate_limited,
            "duration_seconds": self.duration_seconds
        }

    def get_by_type(self, endpoint_type: EndpointType) -> list[DiscoveredEndpoint]:
        """Filter endpoints by type"""
        return [ep for ep in self.endpoints if ep.endpoint_type == endpoint_type]

    def get_authenticated_endpoints(self) -> list[DiscoveredEndpoint]:
        """Get endpoints that require authentication"""
        return [ep for ep in self.endpoints if ep.requires_auth]


class DiscoveryPhase:
    """
    Phase 2: Discovery

    Discovers hidden endpoints and maps the API attack surface.
    Uses wordlists and intelligent fuzzing while respecting rate limits.
    """

    # Common API endpoint wordlists
    COMMON_API_PATHS = [
        # REST API patterns
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/rest/v1", "/rest/v2",
        "/graphql", "/graphql/console",

        # Authentication endpoints
        "/auth", "/auth/login", "/auth/logout", "/auth/register",
        "/auth/callback", "/auth/token", "/auth/refresh",
        "/oauth", "/oauth/authorize", "/oauth/token",
        "/login", "/logout", "/signup", "/register",
        "/.well-known/openid-configuration",
        "/.well-known/jwks.json",

        # Admin/Management
        "/admin", "/admin/login", "/administrator",
        "/manage", "/management", "/dashboard",
        "/console", "/portal", "/cp",

        # Debug/Development (high-risk if exposed)
        "/debug", "/debug/vars", "/debug/pprof",
        "/_debug", "/__debug__",
        "/dev", "/development",
        "/test", "/testing",
        "/staging",

        # Documentation
        "/docs", "/documentation", "/api-docs",
        "/swagger", "/swagger-ui", "/swagger.json",
        "/openapi", "/openapi.json", "/redoc",
        "/api/docs", "/api/swagger",

        # Health/Status
        "/health", "/healthz", "/healthcheck",
        "/status", "/ping", "/ready", "/live",
        "/metrics", "/prometheus",
        "/actuator", "/actuator/health", "/actuator/info",

        # Common resources
        "/users", "/user", "/profile", "/account",
        "/settings", "/config", "/configuration",
        "/files", "/uploads", "/download", "/export",
        "/search", "/query",

        # Database-specific (Supabase)
        "/rest/v1/", "/auth/v1/",
        "/storage/v1/", "/realtime/v1/",
        "/functions/v1/",

        # Firebase
        "/__/firebase/init.json",
        "/.well-known/assetlinks.json",

        # Internal/Hidden
        "/.git", "/.git/config", "/.git/HEAD",
        "/.env", "/.env.local", "/.env.production",
        "/config.json", "/config.yaml", "/config.yml",
        "/package.json", "/composer.json",
        "/.htaccess", "/web.config",
        "/robots.txt", "/sitemap.xml",
        "/.well-known/security.txt",

        # Backup files (high-risk)
        "/backup", "/backups", "/db_backup",
        "/dump.sql", "/database.sql",
    ]

    # Common parameter names to test
    COMMON_PARAMETERS = [
        "id", "user_id", "userId", "uid",
        "page", "limit", "offset", "skip",
        "sort", "order", "orderBy", "sortBy",
        "filter", "query", "q", "search",
        "token", "key", "api_key", "apiKey",
        "callback", "redirect", "return_url", "returnUrl",
        "file", "path", "url", "src",
        "format", "type", "action",
        "debug", "verbose", "test"
    ]

    # Response patterns that indicate different endpoint types
    ENDPOINT_TYPE_PATTERNS = {
        EndpointType.API: [r'"data":', r'"results":', r'"items":', r'"error":'],
        EndpointType.AUTH: [r'token', r'jwt', r'session', r'login', r'password'],
        EndpointType.ADMIN: [r'admin', r'dashboard', r'manage', r'control panel'],
        EndpointType.DEBUG: [r'stack trace', r'debug', r'pprof', r'profiler'],
        EndpointType.DOCUMENTATION: [r'swagger', r'openapi', r'redoc', r'api doc'],
        EndpointType.HEALTH: [r'"status":', r'"healthy"', r'"ok"', r'UP', r'DOWN'],
    }

    # Maximum number of cached results to prevent unbounded memory growth
    MAX_CACHED_RESULTS = 100

    def __init__(self, auth_manager: AuthorizationManager):
        self.auth_manager = auth_manager
        self.results: dict[str, DiscoveryResults] = {}
        self._request_count = 0
        self._last_request_time = 0.0

    def clear_results(self):
        """Clear cached results to free memory"""
        self.results.clear()
        self._request_count = 0

    def _cache_result(self, target: str, result: DiscoveryResults):
        """Cache a result with bounded size"""
        # Prevent unbounded memory growth
        if len(self.results) >= self.MAX_CACHED_RESULTS:
            # Remove oldest entry (first key in dict - Python 3.7+ maintains order)
            oldest_key = next(iter(self.results))
            del self.results[oldest_key]
        self.results[target] = result

    def execute(
        self,
        target: str,
        wordlist: Optional[list[str]] = None,
        methods: Optional[list[HTTPMethod]] = None,
        request_callback: Optional[Callable] = None
    ) -> tuple[bool, DiscoveryResults | str]:
        """
        Execute discovery phase on target.

        Args:
            target: Base URL to discover
            wordlist: Custom wordlist (uses default if None)
            methods: HTTP methods to test (defaults to GET, POST)
            request_callback: Optional callback for making actual HTTP requests

        Returns:
            tuple: (success, DiscoveryResults or error message)
        """
        # Check authorization
        authorized, reason = self.auth_manager.check_authorization(
            target=target,
            phase=TestingPhase.DISCOVERY,
            requires_exploit=False
        )

        if not authorized:
            return False, f"Authorization denied: {reason}"

        paths = wordlist or self.COMMON_API_PATHS
        methods = methods or [HTTPMethod.GET, HTTPMethod.POST]

        results = DiscoveryResults(
            target=target,
            wordlist_used="custom" if wordlist else "default"
        )

        # In a real implementation, this would make HTTP requests
        # The callback pattern allows for actual network operations

        return True, results

    def classify_endpoint(
        self,
        url: str,
        status_code: int,
        response_body: str,
        response_headers: dict
    ) -> EndpointType:
        """
        Classify an endpoint based on response characteristics.

        Args:
            url: The endpoint URL
            status_code: HTTP status code
            response_body: Response body content
            response_headers: Response headers

        Returns:
            EndpointType classification
        """
        url_lower = url.lower()

        # Check URL patterns first
        if any(p in url_lower for p in ['/admin', '/manage', '/dashboard', '/console']):
            return EndpointType.ADMIN
        if any(p in url_lower for p in ['/auth', '/login', '/oauth', '/token']):
            return EndpointType.AUTH
        if any(p in url_lower for p in ['/health', '/status', '/ping', '/ready']):
            return EndpointType.HEALTH
        if any(p in url_lower for p in ['/docs', '/swagger', '/openapi', '/redoc']):
            return EndpointType.DOCUMENTATION
        if any(p in url_lower for p in ['/debug', '/pprof', '/_debug']):
            return EndpointType.DEBUG
        if any(p in url_lower for p in ['/api', '/rest', '/graphql', '/v1', '/v2']):
            return EndpointType.API

        # Check response body patterns
        for endpoint_type, patterns in self.ENDPOINT_TYPE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return endpoint_type

        # Check content type
        content_type = response_headers.get('content-type', '').lower()
        if 'application/json' in content_type:
            return EndpointType.API
        if 'text/html' in content_type:
            if status_code == 200:
                return EndpointType.STATIC

        return EndpointType.UNKNOWN

    def detect_authentication_requirement(
        self,
        status_code: int,
        response_headers: dict,
        response_body: str
    ) -> bool:
        """
        Detect if endpoint requires authentication.

        Args:
            status_code: HTTP status code
            response_headers: Response headers
            response_body: Response body

        Returns:
            bool: True if authentication appears required
        """
        # Status code indicators
        if status_code in [401, 403]:
            return True

        # Header indicators
        if 'www-authenticate' in [h.lower() for h in response_headers]:
            return True

        # Body indicators
        auth_indicators = [
            r'unauthorized',
            r'authentication required',
            r'login required',
            r'access denied',
            r'invalid.*token',
            r'missing.*token',
            r'jwt',
            r'bearer'
        ]

        for pattern in auth_indicators:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True

        return False

    def extract_parameters(self, response_body: str) -> list[str]:
        """
        Extract potential parameter names from response.

        Args:
            response_body: Response body content

        Returns:
            List of discovered parameter names
        """
        parameters = set()

        # JSON key extraction
        json_key_pattern = r'"([a-zA-Z_][a-zA-Z0-9_]*)":'
        matches = re.findall(json_key_pattern, response_body)
        parameters.update(matches)

        # Query parameter extraction from URLs in response
        query_param_pattern = r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)='
        matches = re.findall(query_param_pattern, response_body)
        parameters.update(matches)

        # Form field extraction
        form_field_pattern = r'name=["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']'
        matches = re.findall(form_field_pattern, response_body, re.IGNORECASE)
        parameters.update(matches)

        return list(parameters)

    def generate_api_wordlist(self, base_resources: list[str]) -> list[str]:
        """
        Generate comprehensive API wordlist from base resources.

        Args:
            base_resources: List of resource names (e.g., ["users", "posts"])

        Returns:
            Expanded wordlist with CRUD patterns
        """
        wordlist = []

        for resource in base_resources:
            # Standard REST patterns
            wordlist.extend([
                f"/api/{resource}",
                f"/api/v1/{resource}",
                f"/api/v2/{resource}",
                f"/api/{resource}/list",
                f"/api/{resource}/all",
                f"/api/{resource}/search",
                f"/api/{resource}/export",
                f"/api/{resource}/import",
                f"/api/{resource}/bulk",
                f"/api/{resource}/batch",

                # Singular patterns
                f"/api/{resource[:-1] if resource.endswith('s') else resource}",
                f"/api/{resource}/{{id}}",
                f"/api/{resource}/1",
                f"/api/{resource}/me",
                f"/api/{resource}/current",

                # Admin patterns
                f"/admin/{resource}",
                f"/admin/api/{resource}",
                f"/manage/{resource}",

                # Internal patterns
                f"/internal/{resource}",
                f"/_internal/{resource}",
            ])

        return wordlist

    def get_rate_limiter_config(self) -> dict:
        """
        Get rate limiting configuration.

        Returns:
            dict with rate limiting settings
        """
        if self.auth_manager.scope:
            max_rps = self.auth_manager.scope.max_requests_per_second
        else:
            max_rps = 5  # Conservative default

        return {
            "requests_per_second": max_rps,
            "burst_limit": max_rps * 2,
            "backoff_factor": 2.0,
            "max_backoff_seconds": 60,
            "retry_on_429": True,
            "retry_count": 3
        }

    def should_skip_path(self, path: str, response_history: list[dict]) -> bool:
        """
        Determine if a path should be skipped based on history.

        Implements smart skipping to avoid wasting requests on
        patterns that consistently return 404.

        Args:
            path: Path to evaluate
            response_history: Previous response data

        Returns:
            bool: True if path should be skipped
        """
        # Check for pattern-based 404s
        path_parts = path.strip('/').split('/')

        if len(path_parts) >= 2:
            # Check if parent path returned 404
            parent_path = '/' + '/'.join(path_parts[:-1])
            parent_responses = [
                r for r in response_history
                if r.get('path', '').startswith(parent_path)
            ]

            # If parent consistently 404s, skip children
            if len(parent_responses) >= 3:
                status_codes = [r.get('status_code') for r in parent_responses]
                if all(code == 404 for code in status_codes):
                    return True

        return False

    def get_interesting_endpoints(
        self,
        results: DiscoveryResults
    ) -> dict[str, list[DiscoveredEndpoint]]:
        """
        Categorize endpoints by security interest level.

        Args:
            results: Discovery results

        Returns:
            dict with categorized endpoints
        """
        return {
            "critical": [
                ep for ep in results.endpoints
                if ep.endpoint_type in [EndpointType.ADMIN, EndpointType.DEBUG]
                or any(p in ep.url.lower() for p in ['.env', '.git', 'config', 'backup'])
            ],
            "high": [
                ep for ep in results.endpoints
                if ep.endpoint_type == EndpointType.AUTH
                or ep.status_code in [403, 401]  # Might be bypassable
            ],
            "medium": [
                ep for ep in results.endpoints
                if ep.endpoint_type == EndpointType.API
                and not ep.requires_auth
            ],
            "low": [
                ep for ep in results.endpoints
                if ep.endpoint_type in [
                    EndpointType.DOCUMENTATION,
                    EndpointType.HEALTH,
                    EndpointType.STATIC
                ]
            ]
        }
