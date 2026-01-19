"""
Phase 1: Reconnaissance

Fingerprinting tools for detecting target technology stack.
All methods are passive/non-intrusive and require minimal authorization.

Detectable Technologies:
- Databases: Supabase, MongoDB, PostgreSQL, MySQL, Redis, Firebase
- Frameworks: Express, Django, FastAPI, Rails, Spring
- Cloud Services: AWS, GCP, Azure, Vercel, Netlify
- Authentication: Auth0, Okta, Firebase Auth, Supabase Auth

Mitigations for False Positives:
- Context-aware pattern matching (code vs comments)
- Proper URL path boundary validation
- Source reliability weighting
- Conflict detection for contradictory indicators
"""

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from statistics import mean, stdev
from typing import Optional
from urllib.parse import urlparse
import re
import json
from ..authorization import AuthorizationManager, TestingPhase


# Source reliability profiles for weighted confidence scoring
SOURCE_RELIABILITY = {
    "domain": 0.98,          # Domain match is highly reliable
    "endpoint_structure": 0.90,
    "header_name": 0.82,
    "header_value": 0.70,
    "error_pattern": 0.65,
    "js_pattern": 0.65,
    "body_pattern": 0.60,
    "unknown": 0.50
}


class PatternValidator:
    """Validates pattern matches with contextual rules to reduce false positives."""

    @staticmethod
    def validate_header_pattern(header_name: str, pattern: str) -> tuple[bool, float]:
        """
        Validate header pattern with stricter rules.

        Returns:
            (is_valid_match, adjusted_confidence)
        """
        pattern_lower = pattern.lower()
        header_lower = header_name.lower()

        # Rule 1: Exact header name match is highest confidence
        if header_lower == pattern_lower:
            return True, 1.0

        # Rule 2: Header starts with pattern (more reliable than substring)
        if header_lower.startswith(pattern_lower):
            return True, 0.9

        # Rule 3: Pattern is a complete token in header name
        # Split by common delimiters: -, _, .
        tokens = re.split(r'[-_.]', header_lower)
        pattern_tokens = re.split(r'[-_.]', pattern_lower)

        if all(pt in tokens for pt in pattern_tokens if pt):
            return True, 0.8

        # Rule 4: Reject simple substring matches (too broad)
        return False, 0.0

    @staticmethod
    def is_reliable_header_for_values(header_name: str) -> bool:
        """Check if header value is reliable for fingerprinting."""
        reliable_headers = {
            'server', 'x-powered-by', 'x-aspnet-version',
            'x-framework', 'x-platform', 'x-generator'
        }
        return header_name.lower() in reliable_headers


class CodeContextAnalyzer:
    """Analyzes code patterns with context awareness."""

    @staticmethod
    def extract_context(body: str, match_position: int, window: int = 100) -> str:
        """Extract surrounding context around match."""
        start = max(0, match_position - window)
        end = min(len(body), match_position + window)
        return body[start:end]

    @staticmethod
    def is_likely_comment_or_docs(context: str, pattern: str) -> bool:
        """Determine if pattern match is in comment, string, or documentation."""
        # Find where pattern appears in context
        pattern_pos = context.find(pattern) if pattern in context else len(context) // 2

        # Check for comment indicators before match
        before_match = context[:pattern_pos]
        comment_markers = ['//', '/*', '*', '#', '--', '<!--', '"""', "'''"]

        for marker in comment_markers:
            if marker in before_match:
                # Check if it's on the same line (for single-line comments)
                if marker in ['//', '#', '--']:
                    # Find last newline before match
                    last_newline = before_match.rfind('\n')
                    if marker in before_match[last_newline:]:
                        return True
                # Multi-line comments
                elif marker in ['/*', '<!--', '"""', "'''"]:
                    # Check if closing marker appears
                    closing = {'/*': '*/', '<!--': '-->', '"""': '"""', "'''": "'''"}
                    close = closing.get(marker, '')
                    if close and close not in before_match[before_match.rfind(marker):]:
                        return True

        # Check for documentation patterns
        doc_indicators = ['@param', '@returns', '@example', 'docs:', 'documentation']
        if any(doc in context.lower() for doc in doc_indicators):
            return True

        return False

    @staticmethod
    def is_executable_code(context: str) -> bool:
        """Check if pattern appears to be in executable code."""
        executable_indicators = [
            r'import\s+', r'require\s*\(', r'function\s+',
            r'class\s+', r'const\s+', r'let\s+', r'var\s+',
            r'new\s+', r'=\s*new\s+', r'\.\w+\s*\('
        ]

        return any(
            re.search(indicator, context, re.IGNORECASE)
            for indicator in executable_indicators
        )


class URLValidator:
    """Validates URL patterns with proper path boundary validation."""

    @staticmethod
    def parse_url_path(url: str) -> list[str]:
        """Parse URL into path segments."""
        parsed = urlparse(url)
        return [seg for seg in parsed.path.split('/') if seg]

    @staticmethod
    def validate_endpoint_in_url(endpoint: str, url: str) -> tuple[bool, float]:
        """
        Validate endpoint pattern in URL path structure.

        Prevents false positives from substring matches like
        /api-v2 matching /api endpoint.

        Returns:
            (is_valid_match, confidence)
        """
        endpoint_segments = [seg for seg in endpoint.strip('/').split('/') if seg]
        url_segments = URLValidator.parse_url_path(url)

        if not endpoint_segments:
            return False, 0.0

        # Rule 1: Exact consecutive match in URL segments
        endpoint_str = '/'.join(endpoint_segments)
        url_str = '/'.join(url_segments)

        # Check with boundary
        url_pattern = r'(?:^|/){}(?:$|/)'.format(re.escape(endpoint_str))
        if re.search(url_pattern, '/' + url_str + '/'):
            return True, 0.95

        # Rule 2: Endpoint segments appear consecutively in URL
        for i in range(len(url_segments) - len(endpoint_segments) + 1):
            if url_segments[i:i+len(endpoint_segments)] == endpoint_segments:
                return True, 0.90

        return False, 0.0

    @staticmethod
    def validate_domain_in_url(domain: str, url: str) -> tuple[bool, float]:
        """Validate domain with exact boundary matching."""
        parsed = urlparse(url if '://' in url else f'https://{url}')
        netloc = parsed.netloc.lower()
        domain_lower = domain.lower()

        # Remove port if present
        if ':' in netloc:
            netloc = netloc.split(':')[0]

        # Rule 1: Exact domain match
        if netloc == domain_lower:
            return True, 0.99

        # Rule 2: Domain as subdomain (e.g., api.supabase.co)
        if netloc.endswith('.' + domain_lower):
            return True, 0.95

        # No partial substring matches for domains
        return False, 0.0


class ConflictDetector:
    """Detects mutually exclusive or contradictory indicators."""

    # Technologies that shouldn't coexist at high confidence
    MUTUALLY_EXCLUSIVE = {
        'databases': [
            {'supabase', 'firebase'},  # Both are BaaS, unlikely together
            {'mongodb', 'postgresql', 'mysql'},  # Primary DB choices
        ]
    }

    @staticmethod
    def detect_conflicts(indicators: list[dict]) -> list[str]:
        """
        Identify mutually exclusive technology indicators.

        Returns list of conflict warnings.
        """
        conflicts = []

        # Group by type and get highest confidence for each
        db_detections: dict[str, list[float]] = defaultdict(list)
        for ind in indicators:
            if ind.get("type") == "database":
                db_detections[ind["detected"]].append(ind.get("confidence", 0))

        # Check for conflicting detections
        if len(db_detections) > 1:
            # Get average confidence per database
            db_avg_conf = {
                db: mean(confs)
                for db, confs in db_detections.items()
            }

            # If multiple databases with confidence > 0.7, flag conflict
            high_conf_dbs = {db for db, conf in db_avg_conf.items() if conf > 0.7}

            for exclusive_set in ConflictDetector.MUTUALLY_EXCLUSIVE.get('databases', []):
                overlap = high_conf_dbs & exclusive_set
                if len(overlap) > 1:
                    conflicts.append(
                        f"Multiple high-confidence databases detected: {overlap}. "
                        "Possible false positives - verify manually."
                    )

        return conflicts


class DatabaseType(Enum):
    """Supported database types for detection"""
    SUPABASE = "supabase"
    MONGODB = "mongodb"
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    REDIS = "redis"
    FIREBASE = "firebase"
    DYNAMODB = "dynamodb"
    UNKNOWN = "unknown"


class FrameworkType(Enum):
    """Supported framework types for detection"""
    EXPRESS = "express"
    DJANGO = "django"
    FASTAPI = "fastapi"
    RAILS = "rails"
    SPRING = "spring"
    NEXTJS = "nextjs"
    NUXT = "nuxt"
    LARAVEL = "laravel"
    REACT = "react"
    REMIX = "remix"
    GATSBY = "gatsby"
    UNKNOWN = "unknown"


@dataclass
class TechFingerprint:
    """Results of technology fingerprinting"""
    target: str
    databases: list[DatabaseType] = field(default_factory=list)
    frameworks: list[FrameworkType] = field(default_factory=list)
    cloud_services: list[str] = field(default_factory=list)
    auth_providers: list[str] = field(default_factory=list)
    headers_detected: dict = field(default_factory=dict)
    endpoints_discovered: list[str] = field(default_factory=list)
    confidence_scores: dict = field(default_factory=dict)
    raw_indicators: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "databases": [db.value for db in self.databases],
            "frameworks": [fw.value for fw in self.frameworks],
            "cloud_services": self.cloud_services,
            "auth_providers": self.auth_providers,
            "headers_detected": self.headers_detected,
            "endpoints_discovered": self.endpoints_discovered,
            "confidence_scores": self.confidence_scores
        }


class ReconnaissancePhase:
    """
    Phase 1: Technology Stack Fingerprinting

    This phase performs passive reconnaissance to identify the target's
    technology stack. All methods are non-intrusive and only analyze
    publicly available information.
    """

    # Fingerprint patterns for database detection
    DATABASE_PATTERNS = {
        DatabaseType.SUPABASE: {
            "headers": ["x-supabase-", "sb-"],
            "endpoints": ["/rest/v1/", "/auth/v1/", "/storage/v1/", "/realtime/v1/"],
            "domains": ["supabase.co", "supabase.in"],
            "error_patterns": [r"supabase", r"postgrest"],
            "js_patterns": [r"@supabase/supabase-js", r"createClient.*supabase"]
        },
        DatabaseType.MONGODB: {
            "headers": ["x-mongodb-", "mongodb"],
            "endpoints": ["/api/data/", "/realm/"],
            "domains": ["mongodb.com", "mongodb.net"],
            "error_patterns": [r"MongoError", r"ObjectId", r"BSON"],
            "js_patterns": [r"mongoose", r"mongodb", r"MongoClient"]
        },
        DatabaseType.POSTGRESQL: {
            "headers": ["x-postgres", "x-pg-"],
            "endpoints": [],
            "domains": [],
            "error_patterns": [r"pg_", r"SQLSTATE", r"PostgreSQL", r"psycopg"],
            "js_patterns": [r"pg-promise", r"node-postgres", r"@prisma/client"]
        },
        DatabaseType.MYSQL: {
            "headers": [],
            "endpoints": [],
            "domains": [],
            "error_patterns": [r"mysql_", r"MySQLSyntaxError", r"SQL syntax.*MySQL"],
            "js_patterns": [r"mysql2?", r"sequelize"]
        },
        DatabaseType.FIREBASE: {
            "headers": ["x-firebase-"],
            "endpoints": ["/firebase/", "/__/firebase/"],
            "domains": ["firebaseio.com", "firebase.google.com", "firebaseapp.com"],
            "error_patterns": [r"firebase", r"FirebaseError"],
            "js_patterns": [r"firebase/app", r"@firebase/", r"initializeApp"]
        },
        DatabaseType.REDIS: {
            "headers": ["x-redis-"],
            "endpoints": [],
            "domains": ["redis.io", "redislabs.com"],
            "error_patterns": [r"REDIS", r"RedisError"],
            "js_patterns": [r"ioredis", r"redis"]
        },
        DatabaseType.DYNAMODB: {
            "headers": ["x-amz-"],
            "endpoints": [],
            "domains": ["dynamodb.amazonaws.com"],
            "error_patterns": [r"DynamoDB", r"ValidationException"],
            "js_patterns": [r"@aws-sdk/client-dynamodb", r"aws-sdk.*dynamodb"]
        }
    }

    # Framework detection patterns
    FRAMEWORK_PATTERNS = {
        FrameworkType.EXPRESS: {
            "headers": {"x-powered-by": "Express"},
            "indicators": [r"express", r"app\.listen"]
        },
        FrameworkType.DJANGO: {
            "headers": {"x-frame-options": "SAMEORIGIN", "server": "WSGIServer"},
            "indicators": [r"csrfmiddlewaretoken", r"django"],
            "cookies": ["csrftoken", "sessionid"]
        },
        FrameworkType.FASTAPI: {
            "headers": {},
            "indicators": [r"fastapi", r"starlette"],
            "endpoints": ["/docs", "/redoc", "/openapi.json"]
        },
        FrameworkType.RAILS: {
            "headers": {"x-powered-by": "Phusion Passenger"},
            "indicators": [r"rails", r"turbolinks"],
            "cookies": ["_session_id"]
        },
        FrameworkType.NEXTJS: {
            "headers": {"x-powered-by": "Next.js"},
            "indicators": [r"_next/", r"__NEXT_DATA__", r"next/router", r"next/link"],
            "endpoints": ["/_next/static/", "/_next/image", "/api/"],
            "js_patterns": [r"next/app", r"next/server", r"'use server'", r"'use client'"]
        },
        FrameworkType.REACT: {
            "headers": {},
            "indicators": [
                r"react-dom", r"react\.production", r"react\.development",
                r"__REACT_DEVTOOLS_GLOBAL_HOOK__", r"_reactRootContainer",
                r"data-reactroot", r"data-react-helmet"
            ],
            "js_patterns": [
                r"React\.createElement", r"ReactDOM\.render", r"ReactDOM\.createRoot",
                r"useState\s*\(", r"useEffect\s*\(", r"useContext\s*\(",
                r"from\s+['\"]react['\"]", r"@babel/react"
            ]
        },
        FrameworkType.REMIX: {
            "headers": {},
            "indicators": [r"__remixContext", r"__remixManifest", r"remix-run"],
            "endpoints": ["/_data", "/build/"],
            "js_patterns": [r"@remix-run/", r"useLoaderData", r"useActionData"]
        },
        FrameworkType.GATSBY: {
            "headers": {"x-powered-by": "Gatsby"},
            "indicators": [r"gatsby", r"___gatsby", r"page-data.json"],
            "endpoints": ["/page-data/", "/static/"],
            "js_patterns": [r"gatsby-browser", r"gatsby-ssr", r"@gatsbyjs/"]
        },
        FrameworkType.SPRING: {
            "headers": {},
            "indicators": [r"springframework", r"spring-boot"],
            "endpoints": ["/actuator/health", "/actuator/info"]
        }
    }

    def __init__(self, auth_manager: AuthorizationManager):
        self.auth_manager = auth_manager
        self.results: dict[str, TechFingerprint] = {}

    def execute(self, target: str) -> tuple[bool, TechFingerprint | str]:
        """
        Execute reconnaissance on a target.

        Args:
            target: The target URL or domain

        Returns:
            tuple: (success, TechFingerprint or error message)
        """
        # Check authorization
        authorized, reason = self.auth_manager.check_authorization(
            target=target,
            phase=TestingPhase.RECONNAISSANCE,
            requires_exploit=False
        )

        if not authorized:
            return False, f"Authorization denied: {reason}"

        fingerprint = TechFingerprint(target=target)

        # Note: In a real implementation, these would make actual HTTP requests
        # For this design, we define the analysis logic

        return True, fingerprint

    def analyze_headers(self, headers: dict) -> list[dict]:
        """
        Analyze HTTP headers for technology indicators.

        Uses boundary-aware pattern matching to reduce false positives.

        Args:
            headers: Dict of HTTP response headers

        Returns:
            List of detected indicators with confidence scores
        """
        indicators = []
        validator = PatternValidator()

        for db_type, patterns in self.DATABASE_PATTERNS.items():
            for header_pattern in patterns["headers"]:
                for header_name, header_value in headers.items():
                    # Validate header name match with proper boundaries
                    is_valid, confidence = validator.validate_header_pattern(
                        header_name,
                        header_pattern
                    )

                    if is_valid:
                        indicators.append({
                            "type": "database",
                            "detected": db_type.value,
                            "source": "header_name",
                            "header_name": header_name,
                            "pattern": header_pattern,
                            "confidence": confidence * SOURCE_RELIABILITY["header_name"],
                            "validation_rule": "header_boundary_match"
                        })

                    # Header value matching - only for reliable headers
                    if (header_pattern.lower() in str(header_value).lower() and
                            validator.is_reliable_header_for_values(header_name)):
                        indicators.append({
                            "type": "database",
                            "detected": db_type.value,
                            "source": "header_value",
                            "header_name": header_name,
                            "confidence": SOURCE_RELIABILITY["header_value"],
                            "validation_rule": "reliable_header_value"
                        })

        # Check framework headers with exact matching
        for fw_type, patterns in self.FRAMEWORK_PATTERNS.items():
            if "headers" in patterns and isinstance(patterns["headers"], dict):
                for header_name, expected_value in patterns["headers"].items():
                    # Case-insensitive header lookup
                    headers_lower = {k.lower(): v for k, v in headers.items()}
                    if header_name.lower() in headers_lower:
                        actual_value = headers_lower[header_name.lower()]
                        if expected_value.lower() in str(actual_value).lower():
                            indicators.append({
                                "type": "framework",
                                "detected": fw_type.value,
                                "source": "header",
                                "header_name": header_name,
                                "expected_value": expected_value,
                                "confidence": 0.9,
                                "validation_rule": "exact_header_match"
                            })

        return indicators

    def analyze_response_body(self, body: str) -> list[dict]:
        """
        Analyze response body for technology indicators.

        Uses context-aware matching to distinguish code from comments/docs.

        Args:
            body: The HTTP response body

        Returns:
            List of detected indicators
        """
        indicators = []
        context_analyzer = CodeContextAnalyzer()

        # Check database patterns in error messages or JS
        for db_type, patterns in self.DATABASE_PATTERNS.items():
            for error_pattern in patterns.get("error_patterns", []):
                for match in re.finditer(error_pattern, body, re.IGNORECASE):
                    context = context_analyzer.extract_context(body, match.start())

                    # Skip if likely in comment or documentation
                    if context_analyzer.is_likely_comment_or_docs(context, match.group()):
                        continue

                    # Higher confidence if in executable code context
                    is_executable = context_analyzer.is_executable_code(context)
                    base_confidence = 0.85 if is_executable else 0.55

                    indicators.append({
                        "type": "database",
                        "detected": db_type.value,
                        "source": "error_pattern",
                        "pattern": error_pattern,
                        "confidence": base_confidence * SOURCE_RELIABILITY["error_pattern"],
                        "context_validated": is_executable,
                        "validation_rule": "context_aware"
                    })

            for js_pattern in patterns.get("js_patterns", []):
                for match in re.finditer(js_pattern, body, re.IGNORECASE):
                    context = context_analyzer.extract_context(body, match.start())

                    # Skip if in comments
                    if context_analyzer.is_likely_comment_or_docs(context, match.group()):
                        continue

                    indicators.append({
                        "type": "database",
                        "detected": db_type.value,
                        "source": "js_pattern",
                        "pattern": js_pattern,
                        "confidence": SOURCE_RELIABILITY["js_pattern"],
                        "context_validated": True,
                        "validation_rule": "context_aware"
                    })

        # Check framework patterns with context awareness
        for fw_type, patterns in self.FRAMEWORK_PATTERNS.items():
            for indicator in patterns.get("indicators", []):
                for match in re.finditer(indicator, body, re.IGNORECASE):
                    context = context_analyzer.extract_context(body, match.start())

                    # Skip if in comments/docs
                    if context_analyzer.is_likely_comment_or_docs(context, match.group()):
                        continue

                    is_executable = context_analyzer.is_executable_code(context)
                    base_confidence = 0.75 if is_executable else 0.50

                    indicators.append({
                        "type": "framework",
                        "detected": fw_type.value,
                        "source": "body_pattern",
                        "pattern": indicator,
                        "confidence": base_confidence * SOURCE_RELIABILITY["body_pattern"],
                        "context_validated": is_executable,
                        "validation_rule": "context_aware"
                    })

            # Also check JS-specific patterns for frameworks
            for js_pattern in patterns.get("js_patterns", []):
                for match in re.finditer(js_pattern, body, re.IGNORECASE):
                    context = context_analyzer.extract_context(body, match.start())

                    if context_analyzer.is_likely_comment_or_docs(context, match.group()):
                        continue

                    indicators.append({
                        "type": "framework",
                        "detected": fw_type.value,
                        "source": "js_pattern",
                        "pattern": js_pattern,
                        "confidence": SOURCE_RELIABILITY["js_pattern"],
                        "context_validated": True,
                        "validation_rule": "context_aware"
                    })

        return indicators

    def analyze_urls(self, urls: list[str]) -> list[dict]:
        """
        Analyze discovered URLs for technology indicators.

        Uses proper path boundary validation to prevent false positives
        from substring matches (e.g., /api-v2 matching /api).

        Args:
            urls: List of URLs/endpoints found

        Returns:
            List of detected indicators
        """
        indicators = []
        url_validator = URLValidator()

        for url in urls:
            # Check database-related endpoints with boundary validation
            for db_type, patterns in self.DATABASE_PATTERNS.items():
                for endpoint in patterns.get("endpoints", []):
                    is_valid, confidence = url_validator.validate_endpoint_in_url(
                        endpoint,
                        url
                    )
                    if is_valid:
                        indicators.append({
                            "type": "database",
                            "detected": db_type.value,
                            "source": "endpoint",
                            "url": url,
                            "endpoint": endpoint,
                            "confidence": confidence * SOURCE_RELIABILITY["endpoint_structure"],
                            "validation_rule": "endpoint_boundary"
                        })

                # Domain matching with boundary validation
                for domain in patterns.get("domains", []):
                    is_valid, confidence = url_validator.validate_domain_in_url(
                        domain,
                        url
                    )
                    if is_valid:
                        indicators.append({
                            "type": "database",
                            "detected": db_type.value,
                            "source": "domain",
                            "url": url,
                            "domain": domain,
                            "confidence": confidence * SOURCE_RELIABILITY["domain"],
                            "validation_rule": "domain_boundary"
                        })

            # Check framework endpoints with boundary validation
            for fw_type, patterns in self.FRAMEWORK_PATTERNS.items():
                for endpoint in patterns.get("endpoints", []):
                    is_valid, confidence = url_validator.validate_endpoint_in_url(
                        endpoint,
                        url
                    )
                    if is_valid:
                        indicators.append({
                            "type": "framework",
                            "detected": fw_type.value,
                            "source": "endpoint",
                            "url": url,
                            "endpoint": endpoint,
                            "confidence": confidence * SOURCE_RELIABILITY["endpoint_structure"],
                            "validation_rule": "endpoint_boundary"
                        })

        return indicators

    def consolidate_findings(
        self,
        header_indicators: list[dict],
        body_indicators: list[dict],
        url_indicators: list[dict],
        target: str
    ) -> TechFingerprint:
        """
        Consolidate all indicators into a final fingerprint.

        Uses weighted confidence scoring based on source reliability and
        detects conflicting indicators that may suggest false positives.

        Args:
            header_indicators: Indicators from header analysis
            body_indicators: Indicators from body analysis
            url_indicators: Indicators from URL analysis
            target: The target being fingerprinted

        Returns:
            Consolidated TechFingerprint
        """
        all_indicators = header_indicators + body_indicators + url_indicators
        fingerprint = TechFingerprint(target=target)
        fingerprint.raw_indicators = all_indicators

        # Detect conflicts that may indicate false positives
        conflicts = ConflictDetector.detect_conflicts(all_indicators)
        if conflicts:
            fingerprint.confidence_scores["_conflicts"] = conflicts

        # Group indicators by technology with source tracking
        db_indicators: dict[DatabaseType, list[dict]] = defaultdict(list)
        fw_indicators: dict[FrameworkType, list[dict]] = defaultdict(list)

        for indicator in all_indicators:
            if indicator["type"] == "database":
                db_type = DatabaseType(indicator["detected"])
                db_indicators[db_type].append(indicator)
            elif indicator["type"] == "framework":
                fw_type = FrameworkType(indicator["detected"])
                fw_indicators[fw_type].append(indicator)

        # Calculate weighted confidence for databases
        for db_type, indicators in db_indicators.items():
            final_confidence, metadata = self._calculate_weighted_confidence(indicators)

            # Higher threshold (0.6) to reduce false positives
            if final_confidence >= 0.6:
                fingerprint.databases.append(db_type)
                fingerprint.confidence_scores[f"database_{db_type.value}"] = round(
                    final_confidence, 3
                )
                fingerprint.confidence_scores[f"database_{db_type.value}_metadata"] = metadata

        # Calculate weighted confidence for frameworks
        for fw_type, indicators in fw_indicators.items():
            final_confidence, metadata = self._calculate_weighted_confidence(indicators)

            # Frameworks need slightly higher threshold
            if final_confidence >= 0.65:
                fingerprint.frameworks.append(fw_type)
                fingerprint.confidence_scores[f"framework_{fw_type.value}"] = round(
                    final_confidence, 3
                )
                fingerprint.confidence_scores[f"framework_{fw_type.value}_metadata"] = metadata

        self.results[target] = fingerprint
        return fingerprint

    def _calculate_weighted_confidence(
        self,
        indicators: list[dict],
        source_overlap_penalty: float = 0.1
    ) -> tuple[float, dict]:
        """
        Calculate weighted confidence with source reliability.

        Args:
            indicators: List of indicator dicts with confidence scores
            source_overlap_penalty: Penalty for same-source indicators

        Returns:
            (final_confidence, metadata_dict)
        """
        if not indicators:
            return 0.0, {"reason": "no_indicators"}

        # Get source types and confidences
        sources = [
            ind.get("validation_rule", ind.get("source", "unknown"))
            for ind in indicators
        ]
        confidences = [ind.get("confidence", 0.5) for ind in indicators]

        # Apply source reliability weighting
        weighted_scores = []
        for conf, source in zip(confidences, sources):
            reliability = SOURCE_RELIABILITY.get(source, SOURCE_RELIABILITY["unknown"])
            weighted_scores.append(conf * reliability)

        # Calculate mean
        avg_weighted = mean(weighted_scores)

        # Consistency bonus: if stddev is low, indicators are consistent
        consistency_bonus = 0.0
        std_deviation = 0.0
        if len(weighted_scores) > 1:
            std_deviation = stdev(weighted_scores)
            consistency_bonus = max(0, 0.05 - (std_deviation / 20))

        # Source diversity penalty: same source types are less valuable
        unique_sources = len(set(sources))
        total_sources = len(sources)
        diversity_penalty = 0.0
        if total_sources > 1:
            diversity_penalty = (
                (1.0 - (unique_sources / total_sources)) * source_overlap_penalty
            )

        # Final calculation
        final_confidence = min(
            avg_weighted + consistency_bonus - diversity_penalty,
            1.0
        )

        metadata = {
            "avg_weighted": round(avg_weighted, 3),
            "consistency_bonus": round(consistency_bonus, 3),
            "diversity_penalty": round(diversity_penalty, 3),
            "unique_sources": unique_sources,
            "total_indicators": total_sources,
            "std_deviation": round(std_deviation, 3) if std_deviation else 0
        }

        return final_confidence, metadata

    def get_supabase_indicators(self) -> dict:
        """Return specific indicators for Supabase detection"""
        return {
            "api_endpoints": [
                "/rest/v1/",           # PostgREST API
                "/auth/v1/",           # GoTrue Auth
                "/storage/v1/",        # Storage API
                "/realtime/v1/",       # Realtime subscriptions
                "/functions/v1/"       # Edge Functions
            ],
            "headers": [
                "x-supabase-api-version",
                "sb-token",
                "apikey"
            ],
            "js_sdk_patterns": [
                r"@supabase/supabase-js",
                r"createClient\s*\(\s*['\"]https://.*supabase",
                r"supabase\.auth\.",
                r"supabase\.from\(",
                r"\.select\(.*\)\.eq\("
            ],
            "rls_indicators": [
                "new row violates row-level security",
                "permission denied for table"
            ]
        }

    def get_mongodb_indicators(self) -> dict:
        """Return specific indicators for MongoDB detection"""
        return {
            "api_endpoints": [
                "/api/data/v1/",
                "/api/client/v2.0/"
            ],
            "error_patterns": [
                r"MongoServerError",
                r"MongoNetworkError",
                r"E11000 duplicate key",
                r"ObjectId\(",
                r"\$where",
                r"\$regex"
            ],
            "nosql_injection_test_patterns": [
                r"\{\s*['\"]?\$",       # JSON operator injection
                r"\$ne",
                r"\$gt",
                r"\$lt",
                r"\$or",
                r"\$and"
            ]
        }

    def get_postgres_indicators(self) -> dict:
        """Return specific indicators for PostgreSQL detection"""
        return {
            "error_patterns": [
                r"SQLSTATE\[\d+\]",
                r"pg_catalog",
                r"relation .* does not exist",
                r"column .* does not exist",
                r"unterminated quoted string"
            ],
            "version_detection": [
                r"PostgreSQL \d+\.\d+"
            ]
        }

    def get_react_indicators(self) -> dict:
        """Return specific indicators for React/Next.js detection"""
        return {
            "react_core": {
                "dom_patterns": [
                    r"data-reactroot",
                    r"data-react-helmet",
                    r"_reactRootContainer",
                    r"__REACT_DEVTOOLS_GLOBAL_HOOK__"
                ],
                "js_patterns": [
                    r"React\.createElement",
                    r"ReactDOM\.(render|createRoot|hydrateRoot)",
                    r"react\.production\.min\.js",
                    r"react-dom\.production\.min\.js"
                ],
                "hooks_patterns": [
                    r"useState\s*\(",
                    r"useEffect\s*\(",
                    r"useContext\s*\(",
                    r"useReducer\s*\(",
                    r"useMemo\s*\(",
                    r"useCallback\s*\("
                ]
            },
            "nextjs_specific": {
                "app_router": [
                    r"'use client'",
                    r"'use server'",
                    r"generateStaticParams",
                    r"generateMetadata",
                    r"revalidatePath",
                    r"revalidateTag"
                ],
                "pages_router": [
                    r"getServerSideProps",
                    r"getStaticProps",
                    r"getStaticPaths",
                    r"_app\.tsx?",
                    r"_document\.tsx?"
                ],
                "api_routes": [
                    r"NextResponse\.(json|redirect)",
                    r"NextRequest",
                    r"export\s+(async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH)"
                ],
                "data_exposure": [
                    r"__NEXT_DATA__",
                    r"__N_SSP",  # Server-side props marker
                    r"__N_SSG"   # Static generation marker
                ]
            },
            "react_server_components": {
                "patterns": [
                    r"'use server'",
                    r"server-only",
                    r"client-only",
                    r"experimental_taintObjectReference",
                    r"experimental_taintUniqueValue"
                ],
                "serialization_risks": [
                    r"JSON\.parse\s*\(\s*searchParams",
                    r"JSON\.parse\s*\(\s*cookies",
                    r"await\s+cookies\(\)",
                    r"await\s+headers\(\)"
                ]
            },
            "security_indicators": {
                "xss_risks": [
                    r"dangerouslySetInnerHTML",
                    r"\.innerHTML\s*=",
                    r"document\.write\s*\("
                ],
                "prototype_pollution": [
                    r"Object\.assign\s*\(\s*\{\s*\}\s*,",
                    r"\{\s*\.\.\.(props|params|query)",
                    r"_\.merge\s*\(",
                    r"_\.defaultsDeep\s*\("
                ],
                "sensitive_exposure": [
                    r"process\.env\.(?!NEXT_PUBLIC)",
                    r"(API_KEY|SECRET|PASSWORD|TOKEN)\s*[:=]"
                ]
            },
            "version_detection": {
                "patterns": [
                    r"react@(\d+\.\d+\.\d+)",
                    r"react-dom@(\d+\.\d+\.\d+)",
                    r"next@(\d+\.\d+\.\d+)",
                    r'"react":\s*"[\^~]?(\d+\.\d+)',
                    r'"next":\s*"[\^~]?(\d+\.\d+)'
                ],
                "vulnerable_versions": {
                    "react": {
                        "below": "16.14.0",
                        "cve": ["CVE-2020-7919"]
                    },
                    "next": {
                        "below": "13.4.0",
                        "issues": ["Server Actions security improvements"]
                    }
                }
            }
        }

    def get_remix_indicators(self) -> dict:
        """Return specific indicators for Remix detection"""
        return {
            "core_patterns": [
                r"__remixContext",
                r"__remixManifest",
                r"@remix-run/",
                r"remix\.config"
            ],
            "data_functions": [
                r"useLoaderData\s*\(",
                r"useActionData\s*\(",
                r"useFetcher\s*\(",
                r"useSubmit\s*\(",
                r"export\s+(async\s+)?function\s+loader",
                r"export\s+(async\s+)?function\s+action"
            ],
            "security_patterns": [
                r"redirect\s*\(\s*[^'\"]+\)",  # Unvalidated redirect
                r"json\s*\(\s*\{[^}]*\.\.\.request",  # Spreading request
            ]
        }
