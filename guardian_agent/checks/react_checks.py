"""
React/Frontend Security Checks

Security checks for React, Next.js, and modern frontend applications.
Covers XSS, SSR vulnerabilities, React Server Components, and
client-side security issues.

Updated for React 18+ and Next.js 14+ security considerations.
"""

from dataclasses import dataclass, field
from typing import Optional, Callable
from enum import Enum
import re
import json


class ReactVulnerabilityType(Enum):
    """Types of React-specific vulnerabilities"""
    XSS_DANGEROUS_HTML = "xss_dangerous_html"
    XSS_HREF_JAVASCRIPT = "xss_href_javascript"
    XSS_EVAL_INJECTION = "xss_eval_injection"
    PROTOTYPE_POLLUTION = "prototype_pollution"
    SSR_INJECTION = "ssr_injection"
    RSC_SERIALIZATION = "rsc_serialization"
    HYDRATION_MISMATCH = "hydration_mismatch"
    INSECURE_DEPENDENCY = "insecure_dependency"
    STATE_EXPOSURE = "state_exposure"
    CORS_MISCONFIGURATION = "cors_misconfiguration"


@dataclass
class ReactCheckResult:
    """Result of a React security check"""
    check_id: str
    check_name: str
    vulnerable: bool
    vulnerability_type: Optional[ReactVulnerabilityType]
    severity: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    affected_files: list[str] = field(default_factory=list)
    affected_components: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)


class ReactSecurityChecks:
    """
    Security checks for React and Next.js applications.

    Covers:
    - XSS vulnerabilities (dangerouslySetInnerHTML, href injection)
    - Server-Side Rendering (SSR) security issues
    - React Server Components (RSC) serialization attacks
    - Prototype pollution via props/state
    - Hydration mismatch exploits
    - Client-side state exposure
    - Insecure dependency patterns
    """

    # Patterns for detecting dangerous React code
    DANGEROUS_PATTERNS = {
        "dangerouslySetInnerHTML": {
            "pattern": r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\}\s*\}',
            "safe_pattern": r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*DOMPurify\.sanitize\(',
            "severity": "high",
            "description": "Unsanitized dangerouslySetInnerHTML usage"
        },
        "href_javascript": {
            "pattern": r'href\s*=\s*\{[^}]*\+[^}]*\}|href\s*=\s*\{`[^`]*\$\{',
            "severity": "high",
            "description": "Dynamic href that could allow javascript: protocol"
        },
        "eval_usage": {
            "pattern": r'\beval\s*\(|\bnew\s+Function\s*\(|setTimeout\s*\(\s*[\'"`]|setInterval\s*\(\s*[\'"`]',
            "severity": "critical",
            "description": "Dangerous eval or Function constructor usage"
        },
        "innerHTML_direct": {
            "pattern": r'\.innerHTML\s*=|\.outerHTML\s*=',
            "severity": "high",
            "description": "Direct innerHTML assignment bypassing React"
        },
        "document_write": {
            "pattern": r'document\.write\s*\(|document\.writeln\s*\(',
            "severity": "high",
            "description": "document.write usage"
        },
        "unsafe_url_pattern": {
            "pattern": r'(src|href|action)\s*=\s*\{[^}]*(props|state|params|query|searchParams)[^}]*\}',
            "severity": "medium",
            "description": "URL attribute with unsanitized user input"
        }
    }

    # Next.js specific patterns
    NEXTJS_PATTERNS = {
        "getServerSideProps_injection": {
            "pattern": r'getServerSideProps.*?return\s*\{[^}]*props\s*:\s*\{[^}]*\.\.\.(req|query|params)',
            "severity": "high",
            "description": "Spreading request data directly into props"
        },
        "api_route_injection": {
            "pattern": r'req\.(query|body)\[.*?\](?!\s*\?\?|\s*\|\||\s*&&)',
            "severity": "medium",
            "description": "Unvalidated request parameter access"
        },
        "server_action_exposure": {
            "pattern": r"'use server'[^}]*(?:exec|spawn|eval|require\s*\(\s*[^'\"]\s*\+)",
            "severity": "critical",
            "description": "Potential command injection in Server Action"
        },
        "revalidate_bypass": {
            "pattern": r'revalidatePath\s*\(\s*[^\'\"]+\)|revalidateTag\s*\(\s*[^\'\"]+\)',
            "severity": "medium",
            "description": "Dynamic revalidation path could allow cache poisoning"
        }
    }

    # React Server Components (RSC) patterns
    RSC_PATTERNS = {
        "client_directive_missing": {
            "pattern": r'(?<![\'\"]use client[\'\"].*)(useState|useEffect|useContext|onClick|onChange)\s*[(\=]',
            "severity": "low",
            "description": "Client hooks used without 'use client' directive"
        },
        "serialization_gadget": {
            "pattern": r'JSON\.parse\s*\(\s*(props|searchParams|params)\.',
            "severity": "high",
            "description": "JSON parsing of untrusted props - potential gadget chain"
        },
        "server_only_leak": {
            "pattern": r'(API_KEY|SECRET|PRIVATE|PASSWORD|TOKEN)\s*[=:]\s*[\'"][^\'"]+[\'"]',
            "severity": "critical",
            "description": "Hardcoded secret potentially exposed to client"
        }
    }

    # Prototype pollution patterns
    PROTOTYPE_POLLUTION_PATTERNS = {
        "object_merge": {
            "pattern": r'Object\.assign\s*\(\s*\{\s*\}\s*,\s*(props|state|data|input|params|query)',
            "severity": "medium",
            "description": "Object.assign with untrusted source - prototype pollution risk"
        },
        "spread_untrusted": {
            "pattern": r'\{\s*\.\.\.(props|params|query|body|data)\s*\}',
            "severity": "medium",
            "description": "Spreading untrusted data - prototype pollution risk"
        },
        "lodash_merge": {
            "pattern": r'(_\.merge|_\.defaultsDeep|_\.set)\s*\([^,]+,\s*(props|params|query|body)',
            "severity": "high",
            "description": "Lodash deep merge with untrusted data"
        },
        "bracket_notation": {
            "pattern": r'\[\s*(props|params|query|body|input)\s*\.\s*\w+\s*\]\s*=',
            "severity": "high",
            "description": "Dynamic property assignment with untrusted key"
        }
    }

    def __init__(self, http_callback: Optional[Callable] = None):
        self._http = http_callback

    def check_xss_dangerous_html(
        self,
        source_code: str,
        filename: str = ""
    ) -> ReactCheckResult:
        """
        Check for XSS via dangerouslySetInnerHTML.

        Safe check: Static analysis of source code.
        """
        evidence = []
        vulnerable = False
        affected_components = []

        # Find dangerouslySetInnerHTML usage
        pattern = self.DANGEROUS_PATTERNS["dangerouslySetInnerHTML"]["pattern"]
        safe_pattern = self.DANGEROUS_PATTERNS["dangerouslySetInnerHTML"]["safe_pattern"]

        matches = re.finditer(pattern, source_code, re.MULTILINE | re.DOTALL)

        for match in matches:
            html_source = match.group(1).strip()

            # Check if it's sanitized
            if not re.search(safe_pattern, source_code[max(0, match.start()-100):match.end()]):
                # Check if source is from user input
                if any(unsafe in html_source.lower() for unsafe in
                       ['props', 'state', 'params', 'query', 'input', 'data', 'body']):
                    vulnerable = True
                    evidence.append(f"Unsanitized user input in dangerouslySetInnerHTML: {html_source[:50]}...")

                    # Try to extract component name
                    component_match = re.search(
                        r'(?:function|const|class)\s+(\w+)',
                        source_code[:match.start()][-500:]
                    )
                    if component_match:
                        affected_components.append(component_match.group(1))

        return ReactCheckResult(
            check_id="REACT-001",
            check_name="XSS via dangerouslySetInnerHTML",
            vulnerable=vulnerable,
            vulnerability_type=ReactVulnerabilityType.XSS_DANGEROUS_HTML if vulnerable else None,
            severity="high",
            confidence=0.9 if vulnerable else 0.0,
            evidence=evidence,
            affected_files=[filename] if filename and vulnerable else [],
            affected_components=affected_components,
            remediation=(
                "Sanitize HTML content using DOMPurify before rendering:\n\n"
                "import DOMPurify from 'dompurify';\n\n"
                "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />\n\n"
                "Consider using a markdown renderer with XSS protection instead."
            ),
            references=[
                "https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ]
        )

    def check_xss_href_injection(
        self,
        source_code: str,
        filename: str = ""
    ) -> ReactCheckResult:
        """
        Check for XSS via javascript: protocol in href.

        Detects patterns like: <a href={userInput}>
        """
        evidence = []
        vulnerable = False

        # Pattern for dynamic href
        href_patterns = [
            r'href\s*=\s*\{\s*([^}]+)\s*\}',
            r'href\s*=\s*\{`([^`]+)`\}',
        ]

        for pattern in href_patterns:
            matches = re.finditer(pattern, source_code)
            for match in matches:
                href_value = match.group(1)

                # Check if it's user-controlled without sanitization
                if any(unsafe in href_value.lower() for unsafe in
                       ['props', 'params', 'query', 'input', 'state.url', 'data.url', 'link']):

                    # Check for sanitization
                    context = source_code[max(0, match.start()-200):match.end()+100]
                    if not re.search(r'(sanitize|encodeURI|isValidUrl|validateUrl|URL\()', context, re.IGNORECASE):
                        vulnerable = True
                        evidence.append(f"Unsanitized href: {href_value[:60]}...")

        return ReactCheckResult(
            check_id="REACT-002",
            check_name="XSS via href javascript: protocol",
            vulnerable=vulnerable,
            vulnerability_type=ReactVulnerabilityType.XSS_HREF_JAVASCRIPT if vulnerable else None,
            severity="high",
            confidence=0.85 if vulnerable else 0.0,
            evidence=evidence,
            affected_files=[filename] if filename and vulnerable else [],
            remediation=(
                "Validate URLs before using in href:\n\n"
                "function isSafeUrl(url) {\n"
                "  try {\n"
                "    const parsed = new URL(url, window.location.origin);\n"
                "    return ['http:', 'https:', 'mailto:'].includes(parsed.protocol);\n"
                "  } catch {\n"
                "    return false;\n"
                "  }\n"
                "}\n\n"
                "<a href={isSafeUrl(userUrl) ? userUrl : '#'}>Link</a>"
            ),
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://github.com/cure53/DOMPurify"
            ]
        )

    def check_prototype_pollution(
        self,
        source_code: str,
        filename: str = ""
    ) -> ReactCheckResult:
        """
        Check for prototype pollution vulnerabilities.

        Detects unsafe object merging with user input.
        """
        evidence = []
        vulnerable = False

        for name, config in self.PROTOTYPE_POLLUTION_PATTERNS.items():
            matches = re.finditer(config["pattern"], source_code, re.IGNORECASE)
            for match in matches:
                vulnerable = True
                evidence.append(f"{config['description']}: {match.group(0)[:60]}...")

        return ReactCheckResult(
            check_id="REACT-003",
            check_name="Prototype Pollution",
            vulnerable=vulnerable,
            vulnerability_type=ReactVulnerabilityType.PROTOTYPE_POLLUTION if vulnerable else None,
            severity="medium",
            confidence=0.75 if vulnerable else 0.0,
            evidence=evidence,
            affected_files=[filename] if filename and vulnerable else [],
            remediation=(
                "Prevent prototype pollution:\n\n"
                "1. Create objects with null prototype:\n"
                "   const safe = Object.create(null);\n\n"
                "2. Validate keys before assignment:\n"
                "   if (!['__proto__', 'constructor', 'prototype'].includes(key)) {\n"
                "     obj[key] = value;\n"
                "   }\n\n"
                "3. Use Object.freeze() on sensitive objects\n\n"
                "4. Use libraries like 'safe-flat' for object operations"
            ),
            references=[
                "https://portswigger.net/web-security/prototype-pollution",
                "https://github.com/nicivee/prototype-pollution-attack"
            ]
        )

    def check_nextjs_server_actions(
        self,
        source_code: str,
        filename: str = ""
    ) -> ReactCheckResult:
        """
        Check Next.js Server Actions for security issues.

        Covers:
        - Command injection in server actions
        - SQL injection patterns
        - Unvalidated redirects
        """
        evidence = []
        vulnerable = False

        # Check for 'use server' directive
        if "'use server'" not in source_code and '"use server"' not in source_code:
            return ReactCheckResult(
                check_id="REACT-004",
                check_name="Next.js Server Action Security",
                vulnerable=False,
                vulnerability_type=None,
                severity="info",
                confidence=0.0,
                evidence=["No server actions detected in this file"],
                remediation=""
            )

        # Dangerous patterns in server actions
        dangerous_server_patterns = [
            (r'exec\s*\(\s*[^)]*\+', "Command injection via exec()"),
            (r'spawn\s*\(\s*[^,]*,\s*\[[^\]]*\+', "Command injection via spawn()"),
            (r'eval\s*\(', "eval() in server action"),
            (r'require\s*\(\s*[^\'\"]+\)', "Dynamic require() - potential RCE"),
            (r'redirect\s*\(\s*[^\'\"]+\)', "Unvalidated redirect"),
            (r'sql`[^`]*\$\{[^}]*(formData|input|params)', "Potential SQL injection"),
            (r'prisma\.\w+\.(findMany|findFirst|findUnique)\s*\(\s*\{[^}]*where\s*:\s*\{[^}]*\.\.\.',
             "Prisma query with spread operator - potential injection"),
        ]

        for pattern, description in dangerous_server_patterns:
            matches = re.finditer(pattern, source_code, re.IGNORECASE)
            for match in matches:
                vulnerable = True
                evidence.append(f"{description}: {match.group(0)[:50]}...")

        return ReactCheckResult(
            check_id="REACT-004",
            check_name="Next.js Server Action Security",
            vulnerable=vulnerable,
            vulnerability_type=ReactVulnerabilityType.SSR_INJECTION if vulnerable else None,
            severity="critical" if vulnerable else "info",
            confidence=0.9 if vulnerable else 0.0,
            evidence=evidence,
            affected_files=[filename] if filename and vulnerable else [],
            remediation=(
                "Secure Server Actions:\n\n"
                "1. Validate all inputs with zod or similar:\n"
                "   const schema = z.object({ id: z.string().uuid() });\n"
                "   const validated = schema.parse(formData);\n\n"
                "2. Use parameterized queries:\n"
                "   await prisma.user.findUnique({ where: { id: validated.id } });\n\n"
                "3. Validate redirects against allowlist:\n"
                "   const allowedPaths = ['/dashboard', '/profile'];\n"
                "   if (allowedPaths.includes(path)) redirect(path);\n\n"
                "4. Never use eval() or dynamic require()"
            ),
            references=[
                "https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations",
                "https://nextjs.org/docs/app/building-your-application/authentication"
            ]
        )

    def check_rsc_serialization(
        self,
        source_code: str,
        filename: str = ""
    ) -> ReactCheckResult:
        """
        Check React Server Components for serialization vulnerabilities.

        RSC serializes data to send to client - unsafe deserialization
        or gadget chains could be exploitable.
        """
        evidence = []
        vulnerable = False

        # Patterns that might indicate serialization issues
        rsc_dangerous = [
            (r'JSON\.parse\s*\(\s*searchParams\.', "JSON.parse on searchParams"),
            (r'JSON\.parse\s*\(\s*cookies\(\)', "JSON.parse on cookies"),
            (r'deserialize\s*\(\s*(props|params|searchParams)', "Custom deserialization of user input"),
            (r'new\s+Function\s*\(\s*[^)]*props', "Function constructor with props"),
        ]

        for pattern, description in rsc_dangerous:
            matches = re.finditer(pattern, source_code)
            for match in matches:
                vulnerable = True
                evidence.append(f"{description}: {match.group(0)[:50]}...")

        # Check for secrets in server components that might leak
        secret_patterns = [
            r'process\.env\.((?!NEXT_PUBLIC)[A-Z_]+)',  # Non-public env vars
        ]

        for pattern in secret_patterns:
            matches = re.finditer(pattern, source_code)
            for match in matches:
                # Check if this is actually passed to client
                context = source_code[match.start():match.start()+500]
                if re.search(r'return\s*[{<]|props\s*=', context):
                    evidence.append(f"Server env var may leak to client: {match.group(1)}")

        return ReactCheckResult(
            check_id="REACT-005",
            check_name="RSC Serialization Security",
            vulnerable=vulnerable,
            vulnerability_type=ReactVulnerabilityType.RSC_SERIALIZATION if vulnerable else None,
            severity="high" if vulnerable else "info",
            confidence=0.8 if vulnerable else 0.0,
            evidence=evidence,
            affected_files=[filename] if filename and vulnerable else [],
            remediation=(
                "Secure RSC serialization:\n\n"
                "1. Never JSON.parse untrusted searchParams:\n"
                "   // Bad: JSON.parse(searchParams.data)\n"
                "   // Good: Use zod to validate structure\n\n"
                "2. Mark sensitive data with 'server-only':\n"
                "   import 'server-only';\n\n"
                "3. Use taint API for sensitive data (React 19+):\n"
                "   import { experimental_taintObjectReference } from 'react';\n"
                "   taintObjectReference('Do not pass to client', sensitiveData);"
            ),
            references=[
                "https://react.dev/reference/react/experimental_taintObjectReference",
                "https://nextjs.org/docs/app/building-your-application/rendering/composition-patterns"
            ]
        )

    def check_state_exposure(
        self,
        source_code: str,
        filename: str = ""
    ) -> ReactCheckResult:
        """
        Check for sensitive data exposure in React state/props.

        State is visible in React DevTools and can be extracted.
        """
        evidence = []
        vulnerable = False

        # Patterns for sensitive data in state
        sensitive_state_patterns = [
            (r'useState\s*\(\s*[\'"][^\'"]*(password|secret|token|apiKey|api_key|private)', "Sensitive data in useState"),
            (r'useReducer\s*\([^)]*password|secret|token|apiKey', "Sensitive data in useReducer"),
            (r'this\.state\s*=\s*\{[^}]*(password|secret|token|key)', "Sensitive data in class state"),
            (r'window\.(password|secret|token|apiKey|API_KEY)', "Sensitive data on window object"),
            (r'localStorage\.(setItem|getItem)\s*\([\'"]*(token|password|secret)', "Sensitive data in localStorage"),
        ]

        for pattern, description in sensitive_state_patterns:
            matches = re.finditer(pattern, source_code, re.IGNORECASE)
            for match in matches:
                vulnerable = True
                evidence.append(f"{description}: ...{match.group(0)[:40]}...")

        return ReactCheckResult(
            check_id="REACT-006",
            check_name="Client-Side State Exposure",
            vulnerable=vulnerable,
            vulnerability_type=ReactVulnerabilityType.STATE_EXPOSURE if vulnerable else None,
            severity="medium",
            confidence=0.7 if vulnerable else 0.0,
            evidence=evidence,
            affected_files=[filename] if filename and vulnerable else [],
            remediation=(
                "Protect sensitive data:\n\n"
                "1. Never store secrets in client state\n"
                "2. Use httpOnly cookies for tokens (set by server)\n"
                "3. For temporary secrets, use sessionStorage over localStorage\n"
                "4. Consider using a secure token storage library\n"
                "5. Clear sensitive data when component unmounts"
            ),
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html"
            ]
        )

    def analyze_response_for_react(
        self,
        response_body: str,
        response_headers: dict
    ) -> ReactCheckResult:
        """
        Analyze HTTP response for React security indicators.

        Checks for:
        - React version exposure
        - Development mode in production
        - Missing security headers
        - Exposed source maps
        """
        evidence = []
        indicators = []

        # Check for React version in response
        react_version_pattern = r'react[@/](\d+\.\d+\.\d+)'
        version_match = re.search(react_version_pattern, response_body)
        if version_match:
            version = version_match.group(1)
            indicators.append(f"React version detected: {version}")

            # Check for known vulnerable versions
            major, minor, patch = map(int, version.split('.'))
            if major < 16 or (major == 16 and minor < 14):
                evidence.append(f"Outdated React version {version} - may have known vulnerabilities")

        # Check for development mode
        dev_indicators = [
            'React is running in development mode',
            'development.js',
            '__REACT_DEVTOOLS_GLOBAL_HOOK__',
            'webpack-dev-server',
            '.hot-update.json'
        ]

        for indicator in dev_indicators:
            if indicator in response_body:
                evidence.append(f"Development mode indicator: {indicator}")

        # Check for source maps
        if '.map' in response_body or 'sourceMappingURL' in response_body:
            evidence.append("Source maps may be exposed")

        # Check for __NEXT_DATA__ exposure
        next_data_match = re.search(r'__NEXT_DATA__[^{]*(\{.*?\})\s*</script>', response_body, re.DOTALL)
        if next_data_match:
            try:
                next_data = json.loads(next_data_match.group(1))
                # Check for sensitive data in NEXT_DATA
                data_str = json.dumps(next_data).lower()
                if any(s in data_str for s in ['password', 'secret', 'token', 'apikey', 'private']):
                    evidence.append("Potentially sensitive data in __NEXT_DATA__")
            except json.JSONDecodeError:
                pass

        return ReactCheckResult(
            check_id="REACT-007",
            check_name="React Application Analysis",
            vulnerable=len(evidence) > 0,
            vulnerability_type=None,
            severity="medium" if evidence else "info",
            confidence=0.7,
            evidence=evidence,
            remediation=(
                "Production hardening:\n\n"
                "1. Use production builds: npm run build\n"
                "2. Disable source maps in production\n"
                "3. Remove React DevTools in production\n"
                "4. Update to latest stable React version\n"
                "5. Sanitize data in __NEXT_DATA__"
            ),
            references=[
                "https://react.dev/learn/react-developer-tools"
            ]
        )

    def get_all_checks(self) -> list[dict]:
        """Return metadata for all React security checks"""
        return [
            {
                "id": "REACT-001",
                "name": "XSS via dangerouslySetInnerHTML",
                "category": "safe_check",
                "severity": "high",
                "description": "Detects unsanitized HTML injection"
            },
            {
                "id": "REACT-002",
                "name": "XSS via href javascript: protocol",
                "category": "safe_check",
                "severity": "high",
                "description": "Detects javascript: protocol injection"
            },
            {
                "id": "REACT-003",
                "name": "Prototype Pollution",
                "category": "safe_check",
                "severity": "medium",
                "description": "Detects unsafe object merging"
            },
            {
                "id": "REACT-004",
                "name": "Next.js Server Action Security",
                "category": "safe_check",
                "severity": "critical",
                "description": "Detects injection in Server Actions"
            },
            {
                "id": "REACT-005",
                "name": "RSC Serialization Security",
                "category": "safe_check",
                "severity": "high",
                "description": "Detects RSC serialization issues"
            },
            {
                "id": "REACT-006",
                "name": "Client-Side State Exposure",
                "category": "safe_check",
                "severity": "medium",
                "description": "Detects sensitive data in state"
            },
            {
                "id": "REACT-007",
                "name": "React Application Analysis",
                "category": "safe_check",
                "severity": "medium",
                "description": "Analyzes response for React security issues"
            }
        ]
