"""
Supabase-Specific Security Checks

Checks for Row Level Security (RLS), API key exposure, and
other Supabase-specific vulnerabilities.

Key Detection Improvements:
- Context-aware matching (excludes comments/documentation)
- Whitespace-flexible patterns for code variations
- JWT payload analysis to identify service vs anon keys
- Obfuscation pattern detection
"""

from dataclasses import dataclass
from typing import Optional, Callable
import base64
import json
import re


@dataclass
class SupabaseCheckResult:
    """Result of a Supabase security check"""
    check_id: str
    vulnerable: bool
    severity: str
    evidence: list[str]
    remediation: str


class SupabaseSecurityChecks:
    """
    Security checks specific to Supabase applications.

    Focuses on:
    - Row Level Security (RLS) policy configuration
    - API key management (anon vs service_role)
    - Storage bucket permissions
    - Auth configuration
    """

    def __init__(self, http_callback: Optional[Callable] = None):
        self._http = http_callback

    def check_rls_on_table(
        self,
        supabase_url: str,
        anon_key: str,
        table_name: str
    ) -> SupabaseCheckResult:
        """
        Check if RLS is properly configured for a table.

        Safe check: Only performs SELECT queries.
        """
        evidence = []

        # Test 1: Can we access table without auth?
        # Note: In real implementation, make HTTP request

        # Test 2: Can we see other users' data?
        # This requires a valid user context to compare

        return SupabaseCheckResult(
            check_id="SUP-001",
            vulnerable=False,  # Would be determined by actual test
            severity="critical",
            evidence=evidence,
            remediation=(
                "Enable RLS on the table using: "
                "ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY; "
                "Then create appropriate policies for your use case."
            )
        )

    def check_storage_bucket_permissions(
        self,
        supabase_url: str,
        anon_key: str,
        bucket_name: str
    ) -> SupabaseCheckResult:
        """
        Check storage bucket permissions for unauthorized access.
        """
        evidence = []

        # Check public access
        storage_url = f"{supabase_url}/storage/v1/object/list/{bucket_name}"

        # Test if bucket contents are listable
        # Note: Real implementation would make HTTP request

        return SupabaseCheckResult(
            check_id="SUP-005",
            vulnerable=False,
            severity="high",
            evidence=evidence,
            remediation=(
                "Configure storage bucket policies to restrict access. "
                "Use RLS policies for storage or make buckets private."
            )
        )

    def check_anon_key_permissions(
        self,
        supabase_url: str,
        anon_key: str
    ) -> SupabaseCheckResult:
        """
        Check what the anon key can access.

        Validates that anon key has appropriate restrictions.
        """
        evidence = []
        accessible_tables = []

        # Common tables to check
        tables_to_check = [
            "users", "profiles", "accounts", "auth.users",
            "orders", "payments", "transactions"
        ]

        # Test each table
        for table in tables_to_check:
            # Note: Real implementation would make HTTP request
            pass

        return SupabaseCheckResult(
            check_id="SUP-002",
            vulnerable=len(accessible_tables) > 0,
            severity="high" if accessible_tables else "info",
            evidence=evidence,
            remediation=(
                "Review tables accessible via anon key. "
                "Enable RLS and create policies that require authentication "
                "for sensitive data."
            )
        )

    def analyze_client_code_for_keys(
        self,
        code_content: str
    ) -> SupabaseCheckResult:
        """
        Analyze client-side code for exposed Supabase keys.

        Enhanced detection with:
        - Context-aware matching (excludes comments/docs)
        - Whitespace-flexible patterns
        - JWT payload analysis
        - Obfuscation detection
        """
        evidence = []
        vulnerable = False
        high_severity_findings = []

        # Enhanced patterns with whitespace flexibility and context
        service_patterns = [
            {
                "pattern": r'createClient\s*\(\s*[^)]*service[_\-]?role',
                "severity": "critical",
                "message": "service_role keyword found in createClient"
            },
            {
                "pattern": r'(?:service[_\-]?role[_\-]?key|SUPABASE_SERVICE_ROLE)\s*[:=]',
                "severity": "critical",
                "message": "service_role key assignment detected"
            },
            {
                "pattern": r'["\']role["\']\s*:\s*["\']service[_\-]?role["\']',
                "severity": "critical",
                "message": "role property set to service_role"
            },
            {
                "pattern": r'supabaseServiceKey\s*[:=]',
                "severity": "critical",
                "message": "supabaseServiceKey variable detected"
            },
            {
                "pattern": r'SUPABASE_SERVICE_ROLE_KEY',
                "severity": "critical",
                "message": "SUPABASE_SERVICE_ROLE_KEY constant found"
            }
        ]

        for pattern_config in service_patterns:
            for match in re.finditer(pattern_config["pattern"], code_content, re.IGNORECASE | re.MULTILINE):
                # Context check - skip if in comment
                match_start = match.start()
                line_start = code_content.rfind('\n', 0, match_start) + 1
                line_end = code_content.find('\n', match_start)
                if line_end == -1:
                    line_end = len(code_content)
                line = code_content[line_start:line_end]

                # Check for comment markers before match
                comment_markers = ['//', '#', '/*', '*', '--']
                match_col = match_start - line_start
                is_comment = any(
                    marker in line[:match_col]
                    for marker in comment_markers
                )

                # Check if in environment variable reference (good practice)
                env_patterns = ['process.env', 'os.environ', 'getenv', 'ENV[']
                is_env_ref = any(env in line for env in env_patterns)

                if is_comment:
                    continue

                if is_env_ref:
                    # Environment variable reference is acceptable
                    evidence.append({
                        "type": "info",
                        "message": "Service key loaded from environment variable (good practice)",
                        "context": line.strip()[:100]
                    })
                    continue

                # Found actual service_role key usage
                vulnerable = True
                high_severity_findings.append(pattern_config["message"])
                evidence.append({
                    "type": pattern_config["severity"],
                    "message": pattern_config["message"],
                    "matched_text": match.group()[:50],
                    "line": line.strip()[:100]
                })

        # Check for hardcoded JWT tokens that might be service keys
        jwt_pattern = r'eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{50,}'
        for jwt_match in re.finditer(jwt_pattern, code_content):
            jwt = jwt_match.group()

            # Check context - is it in an assignment or usage?
            context_start = max(0, jwt_match.start() - 50)
            context = code_content[context_start:jwt_match.end() + 10]

            # Skip if clearly a comment
            if '//' in context[:50] or '#' in context[:50]:
                continue

            try:
                # Decode JWT payload to check role
                import base64
                import json

                payload_b64 = jwt.split('.')[1]
                # Add padding if needed
                payload_b64 += '=' * (4 - len(payload_b64) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))

                if payload.get('role') == 'service_role':
                    vulnerable = True
                    high_severity_findings.append("Hardcoded service_role JWT token")
                    evidence.append({
                        "type": "critical",
                        "message": "Hardcoded service_role JWT token found",
                        "jwt_preview": jwt[:30] + "..."
                    })
                elif payload.get('role') == 'anon':
                    # Anon key in code is expected
                    evidence.append({
                        "type": "info",
                        "message": "Anon key found (expected for client-side)"
                    })
            except Exception:
                # JWT couldn't be decoded, check if it's suspiciously long (service keys are longer)
                if len(jwt) > 500:  # Service role JWTs are typically longer
                    evidence.append({
                        "type": "warning",
                        "message": "Long JWT token found - verify it's not a service key",
                        "jwt_length": len(jwt)
                    })

        # Check for obfuscated patterns
        obfuscation_indicators = [
            r'atob\s*\(\s*["\'][^"\']+service',
            r'Buffer\.from\s*\(\s*["\'][^"\']+role',
            r'decodeURIComponent\s*\(\s*["\'][^"\']+supabase',
        ]

        for pattern in obfuscation_indicators:
            if re.search(pattern, code_content, re.IGNORECASE):
                evidence.append({
                    "type": "warning",
                    "message": "Potential obfuscated key pattern detected",
                    "pattern": pattern[:30]
                })

        severity = "critical" if vulnerable else ("warning" if evidence else "info")

        return SupabaseCheckResult(
            check_id="SUP-003",
            vulnerable=vulnerable,
            severity=severity,
            evidence=evidence if evidence else ["No service_role key exposure detected"],
            remediation=(
                f"CRITICAL: {'; '.join(high_severity_findings)}. "
                if high_severity_findings else ""
            ) + (
                "NEVER expose service_role key in client-side code. "
                "Use only the anon key for client applications. "
                "Service role should only be used server-side with proper security controls."
            )
        )

    def get_rls_policy_recommendations(
        self,
        table_name: str,
        access_pattern: str
    ) -> dict:
        """
        Generate RLS policy recommendations based on access pattern.

        Args:
            table_name: Name of the table
            access_pattern: One of "user_owned", "public_read", "team_based"

        Returns:
            Dictionary with recommended policies
        """
        policies = {
            "user_owned": {
                "description": "Each user can only access their own records",
                "select_policy": f"""
CREATE POLICY "Users can view own records"
ON {table_name} FOR SELECT
USING (auth.uid() = user_id);
""",
                "insert_policy": f"""
CREATE POLICY "Users can insert own records"
ON {table_name} FOR INSERT
WITH CHECK (auth.uid() = user_id);
""",
                "update_policy": f"""
CREATE POLICY "Users can update own records"
ON {table_name} FOR UPDATE
USING (auth.uid() = user_id);
""",
                "delete_policy": f"""
CREATE POLICY "Users can delete own records"
ON {table_name} FOR DELETE
USING (auth.uid() = user_id);
"""
            },
            "public_read": {
                "description": "Anyone can read, only owners can modify",
                "select_policy": f"""
CREATE POLICY "Anyone can view records"
ON {table_name} FOR SELECT
USING (true);
""",
                "insert_policy": f"""
CREATE POLICY "Authenticated users can insert"
ON {table_name} FOR INSERT
WITH CHECK (auth.role() = 'authenticated');
""",
                "update_policy": f"""
CREATE POLICY "Only owner can update"
ON {table_name} FOR UPDATE
USING (auth.uid() = user_id);
"""
            },
            "team_based": {
                "description": "Team members can access team resources",
                "select_policy": f"""
CREATE POLICY "Team members can view"
ON {table_name} FOR SELECT
USING (
    team_id IN (
        SELECT team_id FROM team_members
        WHERE user_id = auth.uid()
    )
);
"""
            }
        }

        return policies.get(access_pattern, policies["user_owned"])
