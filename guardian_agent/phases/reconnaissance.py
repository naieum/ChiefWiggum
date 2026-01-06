"""
Phase 1: Reconnaissance

Fingerprinting tools for detecting target technology stack.
All methods are passive/non-intrusive and require minimal authorization.

Detectable Technologies:
- Databases: Supabase, MongoDB, PostgreSQL, MySQL, Redis, Firebase
- Frameworks: Express, Django, FastAPI, Rails, Spring
- Cloud Services: AWS, GCP, Azure, Vercel, Netlify
- Authentication: Auth0, Okta, Firebase Auth, Supabase Auth
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import re
import json
from ..authorization import AuthorizationManager, TestingPhase


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
            "indicators": [r"_next/", r"__NEXT_DATA__"]
        },
        FrameworkType.SPRING: {
            "headers": {},
            "indicators": [r"springframework", r"spring-boot"],
            "endpoints": ["/actuator/health", "/actuator/info"]
        }
    }

    # Maximum number of cached results to prevent unbounded memory growth
    MAX_CACHED_RESULTS = 100

    def __init__(self, auth_manager: AuthorizationManager):
        self.auth_manager = auth_manager
        self.results: dict[str, TechFingerprint] = {}

    def clear_results(self):
        """Clear cached results to free memory"""
        self.results.clear()

    def _cache_result(self, target: str, fingerprint: TechFingerprint):
        """Cache a result with bounded size"""
        # Prevent unbounded memory growth
        if len(self.results) >= self.MAX_CACHED_RESULTS:
            # Remove oldest entry (first key in dict - Python 3.7+ maintains order)
            oldest_key = next(iter(self.results))
            del self.results[oldest_key]
        self.results[target] = fingerprint

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

        Args:
            headers: Dict of HTTP response headers

        Returns:
            List of detected indicators with confidence scores
        """
        indicators = []

        for db_type, patterns in self.DATABASE_PATTERNS.items():
            for header_pattern in patterns["headers"]:
                for header_name, header_value in headers.items():
                    if header_pattern.lower() in header_name.lower():
                        indicators.append({
                            "type": "database",
                            "detected": db_type.value,
                            "source": "header",
                            "header_name": header_name,
                            "confidence": 0.8
                        })
                    if header_pattern.lower() in str(header_value).lower():
                        indicators.append({
                            "type": "database",
                            "detected": db_type.value,
                            "source": "header_value",
                            "header_name": header_name,
                            "confidence": 0.7
                        })

        # Check framework headers
        for fw_type, patterns in self.FRAMEWORK_PATTERNS.items():
            if "headers" in patterns:
                for header_name, expected_value in patterns["headers"].items():
                    if header_name.lower() in [h.lower() for h in headers]:
                        actual_value = headers.get(header_name, "")
                        if expected_value.lower() in actual_value.lower():
                            indicators.append({
                                "type": "framework",
                                "detected": fw_type.value,
                                "source": "header",
                                "confidence": 0.9
                            })

        return indicators

    def analyze_response_body(self, body: str) -> list[dict]:
        """
        Analyze response body for technology indicators.

        Args:
            body: The HTTP response body

        Returns:
            List of detected indicators
        """
        indicators = []

        # Check database patterns in error messages or JS
        for db_type, patterns in self.DATABASE_PATTERNS.items():
            for error_pattern in patterns.get("error_patterns", []):
                if re.search(error_pattern, body, re.IGNORECASE):
                    indicators.append({
                        "type": "database",
                        "detected": db_type.value,
                        "source": "error_pattern",
                        "pattern": error_pattern,
                        "confidence": 0.85
                    })

            for js_pattern in patterns.get("js_patterns", []):
                if re.search(js_pattern, body, re.IGNORECASE):
                    indicators.append({
                        "type": "database",
                        "detected": db_type.value,
                        "source": "js_pattern",
                        "pattern": js_pattern,
                        "confidence": 0.75
                    })

        # Check framework patterns
        for fw_type, patterns in self.FRAMEWORK_PATTERNS.items():
            for indicator in patterns.get("indicators", []):
                if re.search(indicator, body, re.IGNORECASE):
                    indicators.append({
                        "type": "framework",
                        "detected": fw_type.value,
                        "source": "body_pattern",
                        "confidence": 0.7
                    })

        return indicators

    def analyze_urls(self, urls: list[str]) -> list[dict]:
        """
        Analyze discovered URLs for technology indicators.

        Args:
            urls: List of URLs/endpoints found

        Returns:
            List of detected indicators
        """
        indicators = []

        for url in urls:
            # Check database-related endpoints
            for db_type, patterns in self.DATABASE_PATTERNS.items():
                for endpoint in patterns.get("endpoints", []):
                    if endpoint in url:
                        indicators.append({
                            "type": "database",
                            "detected": db_type.value,
                            "source": "endpoint",
                            "url": url,
                            "confidence": 0.9
                        })

                for domain in patterns.get("domains", []):
                    if domain in url:
                        indicators.append({
                            "type": "database",
                            "detected": db_type.value,
                            "source": "domain",
                            "url": url,
                            "confidence": 0.95
                        })

            # Check framework endpoints
            for fw_type, patterns in self.FRAMEWORK_PATTERNS.items():
                for endpoint in patterns.get("endpoints", []):
                    if endpoint in url:
                        indicators.append({
                            "type": "framework",
                            "detected": fw_type.value,
                            "source": "endpoint",
                            "url": url,
                            "confidence": 0.85
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

        # Aggregate confidence scores by technology
        db_scores: dict[DatabaseType, list[float]] = {}
        fw_scores: dict[FrameworkType, list[float]] = {}

        for indicator in all_indicators:
            if indicator["type"] == "database":
                db_type = DatabaseType(indicator["detected"])
                if db_type not in db_scores:
                    db_scores[db_type] = []
                db_scores[db_type].append(indicator["confidence"])
            elif indicator["type"] == "framework":
                fw_type = FrameworkType(indicator["detected"])
                if fw_type not in fw_scores:
                    fw_scores[fw_type] = []
                fw_scores[fw_type].append(indicator["confidence"])

        # Calculate final confidence and add to fingerprint
        for db_type, scores in db_scores.items():
            # Use weighted average with bonus for multiple indicators
            avg_confidence = sum(scores) / len(scores)
            multi_indicator_bonus = min(0.1 * (len(scores) - 1), 0.15)
            final_confidence = min(avg_confidence + multi_indicator_bonus, 1.0)

            if final_confidence >= 0.5:  # Threshold for inclusion
                fingerprint.databases.append(db_type)
                fingerprint.confidence_scores[f"database_{db_type.value}"] = final_confidence

        for fw_type, scores in fw_scores.items():
            avg_confidence = sum(scores) / len(scores)
            multi_indicator_bonus = min(0.1 * (len(scores) - 1), 0.15)
            final_confidence = min(avg_confidence + multi_indicator_bonus, 1.0)

            if final_confidence >= 0.5:
                fingerprint.frameworks.append(fw_type)
                fingerprint.confidence_scores[f"framework_{fw_type.value}"] = final_confidence

        self._cache_result(target, fingerprint)
        return fingerprint

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
