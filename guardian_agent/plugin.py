"""
Guardian-Agent: Claude Plugin for Authorized VAPT Testing

Main plugin orchestrator that coordinates all phases of the
Vulnerability Assessment & Penetration Testing lifecycle.

IMPORTANT: This tool is designed for AUTHORIZED security testing only.
Always obtain proper written authorization before testing any system.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Callable
import json

from .authorization import (
    AuthorizationManager,
    AuthorizationScope,
    AuthorizationLevel,
    TestingPhase
)
from .phases import (
    ReconnaissancePhase,
    DiscoveryPhase,
    TargetedTestingPhase,
    ReportingPhase
)
from .phases.reconnaissance import TechFingerprint, DatabaseType
from .phases.discovery import DiscoveryResults
from .phases.targeted_testing import TestResult
from .phases.reporting import SecurityReport, ReportFormat


class AssessmentStatus(Enum):
    """Status of the security assessment"""
    NOT_STARTED = "not_started"
    AUTHORIZED = "authorized"
    RECONNAISSANCE = "reconnaissance"
    DISCOVERY = "discovery"
    TESTING = "testing"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class AssessmentState:
    """Tracks the current state of an assessment"""
    status: AssessmentStatus = AssessmentStatus.NOT_STARTED
    target: Optional[str] = None
    fingerprint: Optional[TechFingerprint] = None
    discovery_results: Optional[DiscoveryResults] = None
    test_results: list[TestResult] = field(default_factory=list)
    report: Optional[SecurityReport] = None
    errors: list[str] = field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class GuardianAgent:
    """
    Guardian-Agent: VAPT Plugin for Claude

    A comprehensive security assessment tool that follows a strict
    vulnerability assessment and penetration testing lifecycle.

    Key Features:
    - Authorization-first approach: No testing without explicit approval
    - Safe-Check priority: Non-destructive checks run first
    - Exploit-Approval flag: Active testing requires explicit consent
    - Technology-aware: Tests tailored to detected stack
    - Comprehensive reporting: Findings with severity, impact, remediation

    Usage:
        agent = GuardianAgent()

        # Step 1: Set up authorization
        scope = AuthorizationScope(
            target_domains=["example.com"],
            authorization_document="PEN-TEST-2024-001",
            authorized_by="security@example.com"
        )
        agent.authorize(scope, level=AuthorizationLevel.SAFE_CHECK)

        # Step 2: Run assessment
        report = agent.run_full_assessment("https://api.example.com")

        # Step 3: Get report
        print(agent.export_report(ReportFormat.JSON))
    """

    VERSION = "1.0.0"

    def __init__(self):
        """Initialize the Guardian-Agent plugin"""
        self.auth_manager = AuthorizationManager()
        self.state = AssessmentState()

        # Initialize phases
        self.recon = ReconnaissancePhase(self.auth_manager)
        self.discovery = DiscoveryPhase(self.auth_manager)
        self.testing = TargetedTestingPhase(self.auth_manager)
        self.reporting = ReportingPhase(self.auth_manager)

        # Callbacks for actual HTTP operations (to be provided by Claude)
        self._http_callback: Optional[Callable] = None

    def authorize(
        self,
        scope: AuthorizationScope,
        level: AuthorizationLevel = AuthorizationLevel.SAFE_CHECK,
        exploit_approval: bool = False
    ) -> tuple[bool, str]:
        """
        Set up authorization for the assessment.

        CRITICAL: This must be called before any testing can proceed.

        Args:
            scope: Defines the authorized testing boundaries
            level: Authorization level (NONE, SAFE_CHECK, or EXPLOIT_APPROVAL)
            exploit_approval: Explicit flag for exploit-level testing

        Returns:
            tuple: (success, message)

        Example:
            scope = AuthorizationScope(
                target_domains=["api.example.com", "*.example.com"],
                target_ips=["192.168.1.0/24"],
                exclusions=["production.example.com", "*.prod.example.com"],
                authorization_document="PENTEST-2024-001",
                authorized_by="ciso@example.com",
                expiration_date=datetime(2024, 12, 31)
            )

            success, msg = agent.authorize(
                scope=scope,
                level=AuthorizationLevel.SAFE_CHECK,
                exploit_approval=False  # Safe checks only
            )
        """
        # Validate scope requirements
        if not scope.target_domains and not scope.target_ips:
            return False, "Authorization scope must include at least one target domain or IP"

        if level == AuthorizationLevel.EXPLOIT_APPROVAL:
            if not exploit_approval:
                return False, "EXPLOIT_APPROVAL level requires exploit_approval=True"
            if not scope.authorization_document:
                return False, "EXPLOIT_APPROVAL level requires authorization_document reference"

        # Set authorization
        success = self.auth_manager.set_authorization(
            level=level,
            scope=scope,
            exploit_approval=exploit_approval
        )

        if success:
            self.state.status = AssessmentStatus.AUTHORIZED
            return True, f"Authorization granted at level: {level.value}"
        else:
            return False, "Authorization failed - check audit log for details"

    def run_full_assessment(
        self,
        target: str,
        skip_discovery: bool = False,
        custom_wordlist: Optional[list[str]] = None
    ) -> tuple[bool, SecurityReport | str]:
        """
        Run a complete VAPT assessment on the target.

        Executes all phases in sequence:
        1. Reconnaissance - Fingerprint technology stack
        2. Discovery - Map endpoints and attack surface
        3. Targeted Testing - Run appropriate security tests
        4. Reporting - Generate comprehensive report

        Args:
            target: Target URL to assess
            skip_discovery: Skip endpoint discovery phase
            custom_wordlist: Custom wordlist for discovery

        Returns:
            tuple: (success, SecurityReport or error message)

        Note:
            The level of testing depends on authorization:
            - SAFE_CHECK: Only non-destructive tests
            - EXPLOIT_APPROVAL: Full testing including active exploitation
        """
        self.state.target = target
        self.state.started_at = datetime.now()

        # Verify we have authorization
        if self.state.status != AssessmentStatus.AUTHORIZED:
            return False, "Assessment not authorized. Call authorize() first."

        try:
            # Phase 1: Reconnaissance
            self.state.status = AssessmentStatus.RECONNAISSANCE
            recon_success, recon_result = self._run_reconnaissance(target)
            if not recon_success:
                self.state.errors.append(f"Reconnaissance failed: {recon_result}")
                self.state.status = AssessmentStatus.FAILED
                return False, recon_result

            self.state.fingerprint = recon_result

            # Phase 2: Discovery
            if not skip_discovery:
                self.state.status = AssessmentStatus.DISCOVERY
                disc_success, disc_result = self._run_discovery(target, custom_wordlist)
                if not disc_success:
                    self.state.errors.append(f"Discovery failed: {disc_result}")
                    # Continue anyway - discovery failure shouldn't stop testing

                self.state.discovery_results = disc_result if disc_success else None

            # Phase 3: Targeted Testing
            self.state.status = AssessmentStatus.TESTING
            test_success, test_results = self._run_targeted_testing(target)
            if not test_success:
                self.state.errors.append(f"Testing failed: {test_results}")
                self.state.status = AssessmentStatus.FAILED
                return False, test_results

            self.state.test_results = test_results

            # Phase 4: Reporting
            self.state.status = AssessmentStatus.REPORTING
            report = self._generate_report(target)
            self.state.report = report
            self.state.status = AssessmentStatus.COMPLETED
            self.state.completed_at = datetime.now()

            return True, report

        except Exception as e:
            self.state.status = AssessmentStatus.FAILED
            self.state.errors.append(str(e))
            return False, f"Assessment failed: {str(e)}"

    def run_reconnaissance_only(self, target: str) -> tuple[bool, TechFingerprint | str]:
        """
        Run only the reconnaissance phase.

        Useful for understanding the target before full assessment.

        Args:
            target: Target URL

        Returns:
            tuple: (success, TechFingerprint or error)
        """
        return self._run_reconnaissance(target)

    def run_safe_checks_only(
        self,
        target: str,
        fingerprint: Optional[TechFingerprint] = None
    ) -> tuple[bool, list[TestResult] | str]:
        """
        Run only safe (non-destructive) security checks.

        This is the recommended approach for initial testing.
        No active exploitation is performed.

        Args:
            target: Target URL
            fingerprint: Optional pre-computed fingerprint

        Returns:
            tuple: (success, list of TestResults or error)
        """
        if fingerprint is None:
            success, result = self._run_reconnaissance(target)
            if not success:
                return False, result
            fingerprint = result

        return self.testing.execute_safe_checks(target, fingerprint)

    def request_exploit_approval(self) -> dict:
        """
        Get information about what exploit-level testing would involve.

        Call this to understand the implications before enabling
        exploit_approval flag.

        Returns:
            dict with test descriptions and requirements
        """
        if self.state.fingerprint is None:
            return {
                "status": "error",
                "message": "Run reconnaissance first to determine applicable tests"
            }

        plan = self.testing.get_test_execution_plan(self.state.fingerprint)

        return {
            "status": "pending_approval",
            "message": "The following active tests require explicit Exploit-Approval",
            "requires_authorization_document": True,
            "tests_requiring_approval": plan["phase_2_active_tests"],
            "total_active_tests": plan["total_active_tests"],
            "safe_checks_completed": plan["total_safe_checks"],
            "warning": (
                "Active tests may modify application state. "
                "Ensure you have written authorization and a rollback plan."
            ),
            "to_proceed": (
                "Call authorize() with level=AuthorizationLevel.EXPLOIT_APPROVAL "
                "and exploit_approval=True"
            )
        }

    def _run_reconnaissance(self, target: str) -> tuple[bool, TechFingerprint | str]:
        """Execute reconnaissance phase"""
        authorized, reason = self.auth_manager.check_authorization(
            target=target,
            phase=TestingPhase.RECONNAISSANCE,
            requires_exploit=False
        )

        if not authorized:
            return False, f"Reconnaissance not authorized: {reason}"

        return self.recon.execute(target)

    def _run_discovery(
        self,
        target: str,
        wordlist: Optional[list[str]] = None
    ) -> tuple[bool, DiscoveryResults | str]:
        """Execute discovery phase"""
        authorized, reason = self.auth_manager.check_authorization(
            target=target,
            phase=TestingPhase.DISCOVERY,
            requires_exploit=False
        )

        if not authorized:
            return False, f"Discovery not authorized: {reason}"

        return self.discovery.execute(target, wordlist=wordlist)

    def _run_targeted_testing(self, target: str) -> tuple[bool, list[TestResult] | str]:
        """Execute targeted testing phase"""
        if self.state.fingerprint is None:
            return False, "No fingerprint available - run reconnaissance first"

        # Always start with safe checks
        success, results = self.testing.execute_safe_checks(
            target,
            self.state.fingerprint
        )

        if not success:
            return False, results

        # If exploit approval is granted, run active tests
        if self.auth_manager.exploit_approval:
            active_success, active_results = self.testing.execute_active_tests(
                target,
                self.state.fingerprint
            )
            if active_success and isinstance(active_results, list):
                results.extend(active_results)

        return True, results

    def _generate_report(self, target: str) -> SecurityReport:
        """Generate the final security report"""
        return self.reporting.generate_report(
            target=target,
            scope=self.auth_manager.scope,
            fingerprint=self.state.fingerprint,
            discovery_results=self.state.discovery_results,
            test_results=self.state.test_results
        )

    def export_report(self, format: ReportFormat = ReportFormat.JSON) -> str:
        """
        Export the assessment report.

        Args:
            format: Output format (JSON, MARKDOWN, or HTML)

        Returns:
            Formatted report string
        """
        if self.state.report is None:
            return json.dumps({"error": "No report available. Run assessment first."})

        return self.reporting.export_report(self.state.report, format)

    def get_status(self) -> dict:
        """
        Get current assessment status.

        Returns:
            dict with current state information
        """
        return {
            "status": self.state.status.value,
            "target": self.state.target,
            "authorization_level": self.auth_manager.current_level.value,
            "exploit_approval": self.auth_manager.exploit_approval,
            "started_at": self.state.started_at.isoformat() if self.state.started_at else None,
            "completed_at": self.state.completed_at.isoformat() if self.state.completed_at else None,
            "findings_count": len(self.state.test_results) if self.state.test_results else 0,
            "errors": self.state.errors
        }

    def get_audit_log(self) -> list[dict]:
        """
        Get the authorization audit log.

        Returns:
            List of audit log entries
        """
        return self.auth_manager.get_audit_log()

    def cancel_assessment(self) -> bool:
        """
        Cancel an in-progress assessment.

        Returns:
            bool: True if cancelled successfully
        """
        if self.state.status in [AssessmentStatus.COMPLETED, AssessmentStatus.CANCELLED]:
            return False

        self.state.status = AssessmentStatus.CANCELLED
        self.auth_manager.revoke_authorization()
        return True

    def reset(self):
        """Reset the agent for a new assessment"""
        self.auth_manager.revoke_authorization()
        self.state = AssessmentState()

    # ==================== CLAUDE INTEGRATION HELPERS ====================

    def get_tool_definitions(self) -> list[dict]:
        """
        Get tool definitions for Claude integration.

        Returns Claude-compatible tool definitions for the plugin.
        """
        return [
            {
                "name": "guardian_authorize",
                "description": (
                    "Authorize a security assessment. Must be called before any testing. "
                    "Requires target domains/IPs and authorization reference."
                ),
                "input_schema": {
                    "type": "object",
                    "required": ["target_domains", "authorization_document"],
                    "properties": {
                        "target_domains": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of authorized domains"
                        },
                        "target_ips": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of authorized IPs"
                        },
                        "exclusions": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Resources to exclude from testing"
                        },
                        "authorization_document": {
                            "type": "string",
                            "description": "Reference to written authorization"
                        },
                        "level": {
                            "type": "string",
                            "enum": ["safe_check", "exploit"],
                            "description": "Authorization level"
                        },
                        "exploit_approval": {
                            "type": "boolean",
                            "description": "Enable active exploitation testing"
                        }
                    }
                }
            },
            {
                "name": "guardian_assess",
                "description": (
                    "Run a security assessment on an authorized target. "
                    "Performs reconnaissance, discovery, testing, and reporting."
                ),
                "input_schema": {
                    "type": "object",
                    "required": ["target"],
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target URL to assess"
                        },
                        "skip_discovery": {
                            "type": "boolean",
                            "description": "Skip endpoint discovery"
                        }
                    }
                }
            },
            {
                "name": "guardian_safe_check",
                "description": (
                    "Run only non-destructive security checks. "
                    "Does not require Exploit-Approval flag."
                ),
                "input_schema": {
                    "type": "object",
                    "required": ["target"],
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target URL to test"
                        }
                    }
                }
            },
            {
                "name": "guardian_report",
                "description": "Get the security assessment report",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "format": {
                            "type": "string",
                            "enum": ["json", "markdown", "html"],
                            "description": "Report output format"
                        }
                    }
                }
            },
            {
                "name": "guardian_status",
                "description": "Get current assessment status and audit log",
                "input_schema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]

    def handle_tool_call(self, tool_name: str, tool_input: dict) -> dict:
        """
        Handle a Claude tool call.

        Args:
            tool_name: Name of the tool being called
            tool_input: Input parameters

        Returns:
            Tool result dict
        """
        if tool_name == "guardian_authorize":
            scope = AuthorizationScope(
                target_domains=tool_input.get("target_domains", []),
                target_ips=tool_input.get("target_ips", []),
                exclusions=tool_input.get("exclusions", []),
                authorization_document=tool_input.get("authorization_document")
            )

            level_str = tool_input.get("level", "safe_check")
            level = (AuthorizationLevel.EXPLOIT_APPROVAL
                    if level_str == "exploit"
                    else AuthorizationLevel.SAFE_CHECK)

            success, message = self.authorize(
                scope=scope,
                level=level,
                exploit_approval=tool_input.get("exploit_approval", False)
            )

            return {"success": success, "message": message}

        elif tool_name == "guardian_assess":
            success, result = self.run_full_assessment(
                target=tool_input["target"],
                skip_discovery=tool_input.get("skip_discovery", False)
            )

            if success:
                return {
                    "success": True,
                    "summary": result.executive_summary,
                    "findings_count": len(result.findings),
                    "report_id": result.report_id
                }
            return {"success": False, "error": result}

        elif tool_name == "guardian_safe_check":
            success, results = self.run_safe_checks_only(
                target=tool_input["target"]
            )

            if success:
                return {
                    "success": True,
                    "tests_run": len(results),
                    "vulnerabilities_found": sum(1 for r in results if r.vulnerable)
                }
            return {"success": False, "error": results}

        elif tool_name == "guardian_report":
            format_str = tool_input.get("format", "json")
            format_map = {
                "json": ReportFormat.JSON,
                "markdown": ReportFormat.MARKDOWN,
                "html": ReportFormat.HTML
            }
            return {"report": self.export_report(format_map.get(format_str, ReportFormat.JSON))}

        elif tool_name == "guardian_status":
            return {
                "status": self.get_status(),
                "audit_log": self.get_audit_log()
            }

        return {"error": f"Unknown tool: {tool_name}"}
