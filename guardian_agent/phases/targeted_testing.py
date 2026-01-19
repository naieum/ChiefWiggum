"""
Phase 3: Targeted Testing

Decision tree for vulnerability testing based on detected technology stack.
Prioritizes Safe-Checks before any active exploitation.

CRITICAL: Exploitation requires explicit Exploit-Approval flag.
All safe checks are non-destructive and read-only.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable
from ..authorization import AuthorizationManager, TestingPhase, AuthorizationLevel
from .reconnaissance import DatabaseType, FrameworkType, TechFingerprint


class TestCategory(Enum):
    """Categories of security tests"""
    SAFE_CHECK = "safe_check"           # Non-destructive, read-only
    ACTIVE_TEST = "active_test"         # May modify state, requires approval
    EXPLOIT = "exploit"                 # Active exploitation, requires approval


class Severity(Enum):
    """Vulnerability severity levels (CVSS-aligned)"""
    CRITICAL = "critical"   # 9.0-10.0
    HIGH = "high"           # 7.0-8.9
    MEDIUM = "medium"       # 4.0-6.9
    LOW = "low"             # 0.1-3.9
    INFO = "info"           # Informational


@dataclass
class TestCase:
    """Represents a security test case"""
    id: str
    name: str
    description: str
    category: TestCategory
    target_tech: list[str]  # Technologies this test applies to
    severity_if_vulnerable: Severity
    safe_check_available: bool = True
    prerequisites: list[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "target_tech": self.target_tech,
            "severity_if_vulnerable": self.severity_if_vulnerable.value,
            "safe_check_available": self.safe_check_available,
            "remediation": self.remediation
        }


@dataclass
class TestResult:
    """Result of a security test"""
    test_case: TestCase
    vulnerable: bool
    confidence: float  # 0.0 to 1.0
    evidence: list[str] = field(default_factory=list)
    payload_used: Optional[str] = None
    response_indicators: list[str] = field(default_factory=list)
    was_safe_check: bool = True
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_case.id,
            "test_name": self.test_case.name,
            "vulnerable": self.vulnerable,
            "confidence": self.confidence,
            "severity": self.test_case.severity_if_vulnerable.value if self.vulnerable else None,
            "evidence": self.evidence,
            "payload_used": self.payload_used if not self.was_safe_check else "[REDACTED - Safe Check]",
            "was_safe_check": self.was_safe_check,
            "remediation": self.test_case.remediation if self.vulnerable else None,
            "notes": self.notes
        }


class TargetedTestingPhase:
    """
    Phase 3: Targeted Testing

    Implements a decision tree for selecting and executing appropriate
    security tests based on the detected technology stack.

    Key principle: Always run Safe-Checks first, only proceed to
    active testing with explicit Exploit-Approval.
    """

    # Test case definitions organized by target technology
    TEST_CASES = {
        # ==================== SUPABASE TESTS ====================
        "supabase": [
            TestCase(
                id="SUP-001",
                name="Supabase RLS Policy Check",
                description="Test Row Level Security policies for data exposure",
                category=TestCategory.SAFE_CHECK,
                target_tech=["supabase"],
                severity_if_vulnerable=Severity.CRITICAL,
                remediation="Enable and properly configure RLS policies for all tables. "
                           "Use service role key only server-side."
            ),
            TestCase(
                id="SUP-002",
                name="Supabase Anonymous Access Check",
                description="Check if tables are accessible without authentication",
                category=TestCategory.SAFE_CHECK,
                target_tech=["supabase"],
                severity_if_vulnerable=Severity.HIGH,
                remediation="Review anon key permissions. Ensure sensitive tables require authentication."
            ),
            TestCase(
                id="SUP-003",
                name="Supabase API Key Exposure",
                description="Check for exposed service_role key in client-side code",
                category=TestCategory.SAFE_CHECK,
                target_tech=["supabase"],
                severity_if_vulnerable=Severity.CRITICAL,
                remediation="Never expose service_role key in client code. Use only anon key client-side."
            ),
            TestCase(
                id="SUP-004",
                name="Supabase Auth Bypass",
                description="Test for authentication bypass vulnerabilities",
                category=TestCategory.ACTIVE_TEST,
                target_tech=["supabase"],
                severity_if_vulnerable=Severity.CRITICAL,
                safe_check_available=False,
                remediation="Review auth configuration and session handling."
            ),
            TestCase(
                id="SUP-005",
                name="Supabase Storage Permissions",
                description="Check storage bucket permissions for unauthorized access",
                category=TestCategory.SAFE_CHECK,
                target_tech=["supabase"],
                severity_if_vulnerable=Severity.HIGH,
                remediation="Configure storage policies to restrict access appropriately."
            ),
            TestCase(
                id="SUP-006",
                name="Supabase SQL Injection via RPC",
                description="Test RPC functions for SQL injection",
                category=TestCategory.ACTIVE_TEST,
                target_tech=["supabase"],
                severity_if_vulnerable=Severity.CRITICAL,
                safe_check_available=False,
                remediation="Use parameterized queries in all database functions."
            ),
        ],

        # ==================== MONGODB TESTS ====================
        "mongodb": [
            TestCase(
                id="MDB-001",
                name="NoSQL Injection - Operator Injection",
                description="Test for MongoDB operator injection ($ne, $gt, $regex, etc.)",
                category=TestCategory.SAFE_CHECK,
                target_tech=["mongodb"],
                severity_if_vulnerable=Severity.CRITICAL,
                remediation="Sanitize user input. Use MongoDB query builders. "
                           "Disable JavaScript execution if not needed."
            ),
            TestCase(
                id="MDB-002",
                name="NoSQL Injection - JavaScript Injection",
                description="Test for $where clause injection allowing arbitrary JS",
                category=TestCategory.ACTIVE_TEST,
                target_tech=["mongodb"],
                severity_if_vulnerable=Severity.CRITICAL,
                safe_check_available=False,
                remediation="Disable $where and mapReduce. Use aggregation pipeline instead."
            ),
            TestCase(
                id="MDB-003",
                name="MongoDB Authentication Bypass",
                description="Test for authentication bypass via query manipulation",
                category=TestCategory.SAFE_CHECK,
                target_tech=["mongodb"],
                severity_if_vulnerable=Severity.CRITICAL,
                remediation="Enable authentication. Use SCRAM-SHA-256. Implement proper access controls."
            ),
            TestCase(
                id="MDB-004",
                name="MongoDB ObjectId Enumeration",
                description="Test for predictable ObjectId generation enabling IDOR",
                category=TestCategory.SAFE_CHECK,
                target_tech=["mongodb"],
                severity_if_vulnerable=Severity.MEDIUM,
                remediation="Implement proper authorization checks. Don't rely on ObjectId unpredictability."
            ),
            TestCase(
                id="MDB-005",
                name="MongoDB Data Exfiltration via $regex",
                description="Test for data extraction using regex-based attacks",
                category=TestCategory.ACTIVE_TEST,
                target_tech=["mongodb"],
                severity_if_vulnerable=Severity.HIGH,
                safe_check_available=False,
                remediation="Validate and sanitize regex inputs. Limit regex complexity."
            ),
        ],

        # ==================== POSTGRESQL TESTS ====================
        "postgresql": [
            TestCase(
                id="PG-001",
                name="SQL Injection - Error-based",
                description="Test for SQL injection via error messages",
                category=TestCategory.SAFE_CHECK,
                target_tech=["postgresql"],
                severity_if_vulnerable=Severity.CRITICAL,
                remediation="Use parameterized queries. Disable verbose error messages in production."
            ),
            TestCase(
                id="PG-002",
                name="SQL Injection - UNION-based",
                description="Test for data extraction via UNION injection",
                category=TestCategory.ACTIVE_TEST,
                target_tech=["postgresql"],
                severity_if_vulnerable=Severity.CRITICAL,
                safe_check_available=False,
                remediation="Use ORM or parameterized queries exclusively."
            ),
            TestCase(
                id="PG-003",
                name="SQL Injection - Blind Boolean",
                description="Test for blind SQL injection via boolean responses",
                category=TestCategory.ACTIVE_TEST,
                target_tech=["postgresql"],
                severity_if_vulnerable=Severity.HIGH,
                safe_check_available=False,
                remediation="Implement input validation and parameterized queries."
            ),
            TestCase(
                id="PG-004",
                name="PostgreSQL Privilege Escalation",
                description="Test for database privilege escalation paths",
                category=TestCategory.ACTIVE_TEST,
                target_tech=["postgresql"],
                severity_if_vulnerable=Severity.CRITICAL,
                safe_check_available=False,
                remediation="Apply principle of least privilege. Review GRANT statements."
            ),
        ],

        # ==================== GENERIC API TESTS ====================
        "api": [
            TestCase(
                id="API-001",
                name="Broken Object Level Authorization (BOLA/IDOR)",
                description="Test for unauthorized access to other users' resources",
                category=TestCategory.SAFE_CHECK,
                target_tech=["api"],
                severity_if_vulnerable=Severity.HIGH,
                remediation="Implement object-level authorization checks on every request."
            ),
            TestCase(
                id="API-002",
                name="Broken Authentication",
                description="Test authentication mechanisms for weaknesses",
                category=TestCategory.SAFE_CHECK,
                target_tech=["api"],
                severity_if_vulnerable=Severity.CRITICAL,
                remediation="Use strong authentication. Implement rate limiting. Use secure session management."
            ),
            TestCase(
                id="API-003",
                name="Excessive Data Exposure",
                description="Check for sensitive data in API responses",
                category=TestCategory.SAFE_CHECK,
                target_tech=["api"],
                severity_if_vulnerable=Severity.MEDIUM,
                remediation="Filter response data server-side. Never return more data than needed."
            ),
            TestCase(
                id="API-004",
                name="Rate Limiting Check",
                description="Test for missing rate limiting on sensitive endpoints",
                category=TestCategory.SAFE_CHECK,
                target_tech=["api"],
                severity_if_vulnerable=Severity.MEDIUM,
                remediation="Implement rate limiting on all endpoints, especially auth."
            ),
            TestCase(
                id="API-005",
                name="Mass Assignment",
                description="Test for mass assignment / auto-binding vulnerabilities",
                category=TestCategory.ACTIVE_TEST,
                target_tech=["api"],
                severity_if_vulnerable=Severity.HIGH,
                safe_check_available=False,
                remediation="Whitelist allowed properties. Never bind request data directly to models."
            ),
            TestCase(
                id="API-006",
                name="Server-Side Request Forgery (SSRF)",
                description="Test for SSRF vulnerabilities in URL parameters",
                category=TestCategory.ACTIVE_TEST,
                target_tech=["api"],
                severity_if_vulnerable=Severity.HIGH,
                safe_check_available=False,
                remediation="Validate and whitelist allowed URLs. Use allow-lists for internal services."
            ),
        ],

        # ==================== AUTHENTICATION TESTS ====================
        "auth": [
            TestCase(
                id="AUTH-001",
                name="JWT Algorithm Confusion",
                description="Test for JWT 'none' algorithm vulnerability",
                category=TestCategory.SAFE_CHECK,
                target_tech=["auth"],
                severity_if_vulnerable=Severity.CRITICAL,
                remediation="Explicitly specify allowed algorithms. Never accept 'none'."
            ),
            TestCase(
                id="AUTH-002",
                name="JWT Secret Weakness",
                description="Check for weak/common JWT secrets",
                category=TestCategory.SAFE_CHECK,
                target_tech=["auth"],
                severity_if_vulnerable=Severity.CRITICAL,
                remediation="Use strong, random secrets (256+ bits). Rotate secrets regularly."
            ),
            TestCase(
                id="AUTH-003",
                name="Session Fixation",
                description="Test for session fixation vulnerabilities",
                category=TestCategory.ACTIVE_TEST,
                target_tech=["auth"],
                severity_if_vulnerable=Severity.HIGH,
                safe_check_available=False,
                remediation="Regenerate session ID after login. Invalidate old sessions."
            ),
            TestCase(
                id="AUTH-004",
                name="Password Reset Weakness",
                description="Test password reset flow for vulnerabilities",
                category=TestCategory.ACTIVE_TEST,
                target_tech=["auth"],
                severity_if_vulnerable=Severity.HIGH,
                safe_check_available=False,
                remediation="Use secure, time-limited tokens. Verify email ownership."
            ),
        ],

        # ==================== REACT/NEXT.JS TESTS ====================
        "react": [
            TestCase(
                id="REACT-001",
                name="XSS via dangerouslySetInnerHTML",
                description="Test for unsanitized HTML injection via dangerouslySetInnerHTML",
                category=TestCategory.SAFE_CHECK,
                target_tech=["react", "nextjs"],
                severity_if_vulnerable=Severity.HIGH,
                remediation="Use DOMPurify to sanitize HTML: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}"
            ),
            TestCase(
                id="REACT-002",
                name="XSS via href javascript: Protocol",
                description="Test for javascript: protocol injection in href attributes",
                category=TestCategory.SAFE_CHECK,
                target_tech=["react", "nextjs"],
                severity_if_vulnerable=Severity.HIGH,
                remediation="Validate URLs against allowlist of protocols (http:, https:, mailto:). Use URL constructor for validation."
            ),
            TestCase(
                id="REACT-003",
                name="Prototype Pollution",
                description="Test for prototype pollution via object spread/merge operations",
                category=TestCategory.SAFE_CHECK,
                target_tech=["react", "nextjs"],
                severity_if_vulnerable=Severity.MEDIUM,
                remediation="Use Object.create(null) for safe objects. Validate keys before assignment. Freeze sensitive objects."
            ),
            TestCase(
                id="REACT-004",
                name="Next.js Server Action Injection",
                description="Test Server Actions for command/SQL injection vulnerabilities",
                category=TestCategory.SAFE_CHECK,
                target_tech=["nextjs"],
                severity_if_vulnerable=Severity.CRITICAL,
                remediation="Validate all inputs with zod. Use parameterized queries. Never use eval() or dynamic require()."
            ),
            TestCase(
                id="REACT-005",
                name="RSC Serialization Attack",
                description="Test React Server Components for unsafe serialization/deserialization",
                category=TestCategory.SAFE_CHECK,
                target_tech=["react", "nextjs"],
                severity_if_vulnerable=Severity.HIGH,
                remediation="Never JSON.parse untrusted searchParams. Use 'server-only' for sensitive code. Use taint API for secrets."
            ),
            TestCase(
                id="REACT-006",
                name="Client State Secret Exposure",
                description="Check for sensitive data exposure in React state (visible in DevTools)",
                category=TestCategory.SAFE_CHECK,
                target_tech=["react", "nextjs"],
                severity_if_vulnerable=Severity.MEDIUM,
                remediation="Never store secrets in client state. Use httpOnly cookies for tokens. Clear sensitive data on unmount."
            ),
            TestCase(
                id="REACT-007",
                name="__NEXT_DATA__ Sensitive Exposure",
                description="Check for sensitive data leakage in __NEXT_DATA__ script tag",
                category=TestCategory.SAFE_CHECK,
                target_tech=["nextjs"],
                severity_if_vulnerable=Severity.MEDIUM,
                remediation="Filter sensitive data in getServerSideProps/getStaticProps. Never pass secrets to page props."
            ),
            TestCase(
                id="REACT-008",
                name="Development Mode in Production",
                description="Detect React/Next.js running in development mode in production",
                category=TestCategory.SAFE_CHECK,
                target_tech=["react", "nextjs"],
                severity_if_vulnerable=Severity.LOW,
                remediation="Use production builds: NODE_ENV=production npm run build. Remove React DevTools in production."
            ),
            TestCase(
                id="REACT-009",
                name="Source Map Exposure",
                description="Check for exposed source maps revealing source code",
                category=TestCategory.SAFE_CHECK,
                target_tech=["react", "nextjs"],
                severity_if_vulnerable=Severity.MEDIUM,
                remediation="Disable source maps in production: productionBrowserSourceMaps: false in next.config.js"
            ),
            TestCase(
                id="REACT-010",
                name="Unvalidated Redirect in Server Actions",
                description="Test for open redirect vulnerabilities in Next.js redirect()",
                category=TestCategory.ACTIVE_TEST,
                target_tech=["nextjs"],
                severity_if_vulnerable=Severity.MEDIUM,
                safe_check_available=False,
                remediation="Validate redirect paths against allowlist. Never redirect to user-controlled URLs directly."
            ),
            TestCase(
                id="REACT-011",
                name="Server Action CSRF",
                description="Test Server Actions for CSRF protection bypass",
                category=TestCategory.ACTIVE_TEST,
                target_tech=["nextjs"],
                severity_if_vulnerable=Severity.HIGH,
                safe_check_available=False,
                remediation="Ensure Server Actions use proper origin validation. Add custom CSRF tokens for sensitive actions."
            ),
            TestCase(
                id="REACT-012",
                name="Hydration Mismatch Exploitation",
                description="Test for security issues arising from SSR/client hydration mismatches",
                category=TestCategory.ACTIVE_TEST,
                target_tech=["react", "nextjs"],
                severity_if_vulnerable=Severity.MEDIUM,
                safe_check_available=False,
                remediation="Ensure server and client render identical content. Use useEffect for client-only operations."
            ),
        ],

        # ==================== REMIX TESTS ====================
        "remix": [
            TestCase(
                id="REMIX-001",
                name="Loader Data Injection",
                description="Test loader functions for injection vulnerabilities",
                category=TestCategory.SAFE_CHECK,
                target_tech=["remix"],
                severity_if_vulnerable=Severity.HIGH,
                remediation="Validate all params in loaders. Use parameterized database queries."
            ),
            TestCase(
                id="REMIX-002",
                name="Action Function Injection",
                description="Test action functions for command/SQL injection",
                category=TestCategory.SAFE_CHECK,
                target_tech=["remix"],
                severity_if_vulnerable=Severity.CRITICAL,
                remediation="Validate formData with zod. Never pass raw input to shell commands or queries."
            ),
            TestCase(
                id="REMIX-003",
                name="Unvalidated Redirect",
                description="Test for open redirect in Remix redirect() calls",
                category=TestCategory.ACTIVE_TEST,
                target_tech=["remix"],
                severity_if_vulnerable=Severity.MEDIUM,
                safe_check_available=False,
                remediation="Validate redirect URLs against allowlist of paths."
            ),
        ],
    }

    # Decision tree for test selection (databases)
    DECISION_TREE = {
        DatabaseType.SUPABASE: {
            "priority_tests": ["SUP-001", "SUP-002", "SUP-003", "SUP-005"],
            "requires_approval": ["SUP-004", "SUP-006"],
            "follow_up_on_vulnerable": {
                "SUP-001": ["SUP-004"],  # If RLS weak, try auth bypass
                "SUP-002": ["SUP-006"],  # If anon access, try SQL injection
            }
        },
        DatabaseType.MONGODB: {
            "priority_tests": ["MDB-001", "MDB-003", "MDB-004"],
            "requires_approval": ["MDB-002", "MDB-005"],
            "follow_up_on_vulnerable": {
                "MDB-001": ["MDB-002", "MDB-005"],  # If operator injection, try JS injection
            }
        },
        DatabaseType.POSTGRESQL: {
            "priority_tests": ["PG-001"],
            "requires_approval": ["PG-002", "PG-003", "PG-004"],
            "follow_up_on_vulnerable": {
                "PG-001": ["PG-002", "PG-003"],  # If error-based works, try UNION/blind
            }
        },
    }

    # Decision tree for frameworks
    FRAMEWORK_DECISION_TREE = {
        FrameworkType.REACT: {
            "priority_tests": [
                "REACT-001", "REACT-002", "REACT-003",  # XSS and prototype pollution
                "REACT-006", "REACT-008", "REACT-009"   # State exposure, dev mode, source maps
            ],
            "requires_approval": ["REACT-012"],  # Hydration exploitation
            "follow_up_on_vulnerable": {
                "REACT-001": ["REACT-012"],  # If XSS found, check hydration issues
                "REACT-003": ["REACT-012"],  # If prototype pollution, check hydration
            }
        },
        FrameworkType.NEXTJS: {
            "priority_tests": [
                "REACT-001", "REACT-002", "REACT-003",  # Core React XSS checks
                "REACT-004", "REACT-005",               # Server Actions and RSC
                "REACT-006", "REACT-007",               # State and __NEXT_DATA__ exposure
                "REACT-008", "REACT-009"                # Dev mode and source maps
            ],
            "requires_approval": ["REACT-010", "REACT-011", "REACT-012"],
            "follow_up_on_vulnerable": {
                "REACT-004": ["REACT-010", "REACT-011"],  # If Server Action issues, test redirects and CSRF
                "REACT-005": ["REACT-012"],               # If RSC serialization issues, test hydration
                "REACT-007": ["REACT-005"],               # If data exposure, deeper RSC checks
            }
        },
        FrameworkType.REMIX: {
            "priority_tests": ["REMIX-001", "REMIX-002"],
            "requires_approval": ["REMIX-003"],
            "follow_up_on_vulnerable": {
                "REMIX-001": ["REMIX-003"],  # If loader injection, test redirects
                "REMIX-002": ["REMIX-003"],  # If action injection, test redirects
            }
        },
        FrameworkType.GATSBY: {
            "priority_tests": [
                "REACT-001", "REACT-002", "REACT-003",  # Core React checks
                "REACT-006", "REACT-008", "REACT-009"   # State, dev mode, source maps
            ],
            "requires_approval": [],
            "follow_up_on_vulnerable": {}
        },
    }

    def __init__(self, auth_manager: AuthorizationManager):
        self.auth_manager = auth_manager
        self.results: list[TestResult] = []

    def get_tests_for_fingerprint(
        self,
        fingerprint: TechFingerprint,
        include_exploit_tests: bool = False
    ) -> list[TestCase]:
        """
        Get applicable tests based on technology fingerprint.

        Args:
            fingerprint: Technology fingerprint from reconnaissance
            include_exploit_tests: Whether to include tests requiring approval

        Returns:
            List of applicable test cases
        """
        applicable_tests = []

        # Always include generic API tests
        applicable_tests.extend(self.TEST_CASES.get("api", []))
        applicable_tests.extend(self.TEST_CASES.get("auth", []))

        # Add database-specific tests
        for db in fingerprint.databases:
            db_key = db.value.lower()
            if db_key in self.TEST_CASES:
                tests = self.TEST_CASES[db_key]
                if not include_exploit_tests:
                    tests = [t for t in tests if t.category == TestCategory.SAFE_CHECK]
                applicable_tests.extend(tests)

        # Add framework-specific tests (React, Next.js, Remix, etc.)
        for fw in fingerprint.frameworks:
            fw_key = fw.value.lower()
            if fw_key in self.TEST_CASES:
                tests = self.TEST_CASES[fw_key]
                if not include_exploit_tests:
                    tests = [t for t in tests if t.category == TestCategory.SAFE_CHECK]
                applicable_tests.extend(tests)

            # Special case: Next.js also gets React tests
            if fw == FrameworkType.NEXTJS and "react" in self.TEST_CASES:
                react_tests = self.TEST_CASES["react"]
                if not include_exploit_tests:
                    react_tests = [t for t in react_tests if t.category == TestCategory.SAFE_CHECK]
                applicable_tests.extend(react_tests)

            # Remix also gets some React tests (XSS checks)
            if fw == FrameworkType.REMIX and "react" in self.TEST_CASES:
                react_tests = [t for t in self.TEST_CASES["react"]
                              if t.id in ["REACT-001", "REACT-002", "REACT-003"]]
                if not include_exploit_tests:
                    react_tests = [t for t in react_tests if t.category == TestCategory.SAFE_CHECK]
                applicable_tests.extend(react_tests)

        # Deduplicate
        seen_ids = set()
        unique_tests = []
        for test in applicable_tests:
            if test.id not in seen_ids:
                seen_ids.add(test.id)
                unique_tests.append(test)

        return unique_tests

    def get_test_execution_plan(
        self,
        fingerprint: TechFingerprint
    ) -> dict:
        """
        Generate a test execution plan based on the decision tree.

        Args:
            fingerprint: Technology fingerprint

        Returns:
            Execution plan with phases and tests
        """
        plan = {
            "phase_1_safe_checks": [],
            "phase_2_active_tests": [],  # Requires approval
            "conditional_tests": {},      # Based on phase 1 results
            "total_safe_checks": 0,
            "total_active_tests": 0,
            "requires_exploit_approval": False
        }

        added_test_ids = set()  # Track added tests to avoid duplicates

        # Process database-specific tests
        for db in fingerprint.databases:
            if db in self.DECISION_TREE:
                tree = self.DECISION_TREE[db]

                # Phase 1: Safe checks (priority tests)
                for test_id in tree.get("priority_tests", []):
                    if test_id not in added_test_ids:
                        test = self._find_test_by_id(test_id)
                        if test and test.category == TestCategory.SAFE_CHECK:
                            plan["phase_1_safe_checks"].append(test.to_dict())
                            added_test_ids.add(test_id)

                # Phase 2: Tests requiring approval
                for test_id in tree.get("requires_approval", []):
                    if test_id not in added_test_ids:
                        test = self._find_test_by_id(test_id)
                        if test:
                            plan["phase_2_active_tests"].append(test.to_dict())
                            plan["requires_exploit_approval"] = True
                            added_test_ids.add(test_id)

                # Conditional follow-ups
                plan["conditional_tests"][db.value] = tree.get("follow_up_on_vulnerable", {})

        # Process framework-specific tests (React, Next.js, Remix, etc.)
        for fw in fingerprint.frameworks:
            if fw in self.FRAMEWORK_DECISION_TREE:
                tree = self.FRAMEWORK_DECISION_TREE[fw]

                # Phase 1: Safe checks (priority tests)
                for test_id in tree.get("priority_tests", []):
                    if test_id not in added_test_ids:
                        test = self._find_test_by_id(test_id)
                        if test and test.category == TestCategory.SAFE_CHECK:
                            plan["phase_1_safe_checks"].append(test.to_dict())
                            added_test_ids.add(test_id)

                # Phase 2: Tests requiring approval
                for test_id in tree.get("requires_approval", []):
                    if test_id not in added_test_ids:
                        test = self._find_test_by_id(test_id)
                        if test:
                            plan["phase_2_active_tests"].append(test.to_dict())
                            plan["requires_exploit_approval"] = True
                            added_test_ids.add(test_id)

                # Conditional follow-ups
                plan["conditional_tests"][fw.value] = tree.get("follow_up_on_vulnerable", {})

        # Add generic API tests to phase 1
        for test in self.TEST_CASES.get("api", []):
            if test.category == TestCategory.SAFE_CHECK:
                if test.id not in added_test_ids:
                    plan["phase_1_safe_checks"].append(test.to_dict())
                    added_test_ids.add(test.id)

        plan["total_safe_checks"] = len(plan["phase_1_safe_checks"])
        plan["total_active_tests"] = len(plan["phase_2_active_tests"])

        return plan

    def execute_safe_checks(
        self,
        target: str,
        fingerprint: TechFingerprint,
        test_executor: Optional[Callable] = None
    ) -> tuple[bool, list[TestResult] | str]:
        """
        Execute only safe (non-destructive) checks.

        Args:
            target: Target to test
            fingerprint: Technology fingerprint
            test_executor: Optional callback for executing actual tests

        Returns:
            tuple: (success, list of TestResults or error message)
        """
        authorized, reason = self.auth_manager.check_authorization(
            target=target,
            phase=TestingPhase.TARGETED_TESTING,
            requires_exploit=False
        )

        if not authorized:
            return False, f"Authorization denied: {reason}"

        safe_tests = [
            t for t in self.get_tests_for_fingerprint(fingerprint, include_exploit_tests=False)
            if t.category == TestCategory.SAFE_CHECK
        ]

        results = []
        # In real implementation, execute each test via callback
        # Results would be populated from actual test execution

        return True, results

    def execute_active_tests(
        self,
        target: str,
        fingerprint: TechFingerprint,
        test_ids: Optional[list[str]] = None,
        test_executor: Optional[Callable] = None
    ) -> tuple[bool, list[TestResult] | str]:
        """
        Execute active tests (requires Exploit-Approval).

        Args:
            target: Target to test
            fingerprint: Technology fingerprint
            test_ids: Specific tests to run (or all applicable if None)
            test_executor: Callback for executing tests

        Returns:
            tuple: (success, list of TestResults or error message)
        """
        # CRITICAL: Check for exploit approval
        authorized, reason = self.auth_manager.check_authorization(
            target=target,
            phase=TestingPhase.TARGETED_TESTING,
            requires_exploit=True  # Requires explicit approval
        )

        if not authorized:
            return False, f"Authorization denied: {reason}. Active tests require Exploit-Approval flag."

        if self.auth_manager.current_level != AuthorizationLevel.EXPLOIT_APPROVAL:
            return False, "Active tests require EXPLOIT_APPROVAL authorization level"

        if not self.auth_manager.exploit_approval:
            return False, "Exploit-Approval flag must be explicitly set to True"

        # Get applicable tests
        all_tests = self.get_tests_for_fingerprint(fingerprint, include_exploit_tests=True)
        active_tests = [t for t in all_tests if t.category in [TestCategory.ACTIVE_TEST, TestCategory.EXPLOIT]]

        if test_ids:
            active_tests = [t for t in active_tests if t.id in test_ids]

        results = []
        # In real implementation, execute tests via callback

        return True, results

    def _find_test_by_id(self, test_id: str) -> Optional[TestCase]:
        """Find a test case by its ID"""
        for category_tests in self.TEST_CASES.values():
            for test in category_tests:
                if test.id == test_id:
                    return test
        return None

    # ==================== SAFE CHECK IMPLEMENTATIONS ====================

    def safe_check_supabase_rls(self, endpoint: str, anon_key: str) -> dict:
        """
        Safe check for Supabase RLS policy configuration.

        This is a non-destructive check that only reads data.
        """
        return {
            "test_id": "SUP-001",
            "method": "safe_check",
            "checks": [
                {
                    "name": "List tables without auth",
                    "request": f"GET {endpoint}/rest/v1/",
                    "headers": {"apikey": anon_key},
                    "vulnerable_if": "Returns table data without authentication"
                },
                {
                    "name": "Check RLS enabled",
                    "request": f"GET {endpoint}/rest/v1/rpc/check_rls_enabled",
                    "note": "Custom function would need to exist"
                }
            ],
            "indicators": {
                "vulnerable": [
                    "Returns 200 with data on sensitive tables",
                    "No 'permission denied' errors",
                    "RLS policy returns false"
                ],
                "secure": [
                    "Returns 401/403 without valid auth",
                    "'new row violates row-level security'",
                    "Empty results on sensitive tables"
                ]
            }
        }

    def safe_check_nosql_injection(self, endpoint: str, param: str) -> dict:
        """
        Safe check for NoSQL injection without data modification.

        Uses detection payloads that don't modify data.
        """
        return {
            "test_id": "MDB-001",
            "method": "safe_check",
            "payloads": [
                # These payloads detect injection without modifying data
                {"param": param, "value": '{"$ne": null}', "type": "operator"},
                {"param": param, "value": '{"$gt": ""}', "type": "operator"},
                {"param": param, "value": '{"$regex": ".*"}', "type": "regex"},
            ],
            "detection": {
                "vulnerable_indicators": [
                    "Returns more results than expected",
                    "Different response for $ne vs normal value",
                    "No input validation error"
                ],
                "timing_based": [
                    "Response time differs significantly with regex"
                ]
            },
            "note": "Safe check only detects presence of vulnerability, does not exploit"
        }

    def safe_check_sql_injection_error(self, endpoint: str, param: str) -> dict:
        """
        Safe check for SQL injection via error messages.

        Uses single quote to detect SQL errors without data extraction.
        """
        return {
            "test_id": "PG-001",
            "method": "safe_check",
            "payloads": [
                {"param": param, "value": "'", "type": "syntax_break"},
                {"param": param, "value": "1'--", "type": "comment"},
                {"param": param, "value": "1 AND 1=1", "type": "boolean"},
            ],
            "detection": {
                "vulnerable_indicators": [
                    "SQLSTATE error in response",
                    "syntax error at or near",
                    "unterminated quoted string",
                    "PostgreSQL error message"
                ],
                "response_diff": "Different response between AND 1=1 and AND 1=2"
            },
            "note": "Does not attempt data extraction"
        }

    def safe_check_jwt_algorithm(self, token: str) -> dict:
        """
        Safe check for JWT algorithm confusion vulnerability.

        Analyzes token structure without making authenticated requests.
        """
        return {
            "test_id": "AUTH-001",
            "method": "safe_check",
            "analysis": [
                {
                    "step": "Decode header (base64)",
                    "check": "Algorithm field value"
                },
                {
                    "step": "Check for 'none' acceptance",
                    "method": "Modify alg to 'none', remove signature"
                },
                {
                    "step": "Check for alg switching",
                    "method": "RS256 -> HS256 with public key as secret"
                }
            ],
            "vulnerable_if": [
                "Server accepts token with alg: 'none'",
                "Server accepts HS256 token when expecting RS256"
            ]
        }
