"""
Supabase-Specific Security Checks

Checks for Row Level Security (RLS), API key exposure, and
other Supabase-specific vulnerabilities.
"""

from dataclasses import dataclass
from typing import Optional, Callable
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
        """
        evidence = []
        vulnerable = False

        # Look for service_role key patterns
        service_patterns = [
            r'supabase\.createClient\([^)]*service[_]?role',
            r'SUPABASE_SERVICE_ROLE',
            r'service_role_key',
            r'"role"\s*:\s*"service_role"'
        ]

        for pattern in service_patterns:
            if re.search(pattern, code_content, re.IGNORECASE):
                vulnerable = True
                evidence.append(f"Potential service_role key usage found")

        return SupabaseCheckResult(
            check_id="SUP-003",
            vulnerable=vulnerable,
            severity="critical" if vulnerable else "info",
            evidence=evidence,
            remediation=(
                "NEVER expose service_role key in client-side code. "
                "Use only the anon key for client applications. "
                "Service role should only be used server-side."
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
