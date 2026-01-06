"""
Authorization Management for Guardian-Agent

Ensures all testing activities are properly authorized and scoped.
No testing can occur without explicit authorization.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import hashlib
import json


class AuthorizationLevel(Enum):
    """Levels of testing authorization"""
    NONE = "none"                    # No authorization - only passive info gathering
    SAFE_CHECK = "safe_check"        # Non-destructive checks only
    EXPLOIT_APPROVAL = "exploit"     # Full testing including active exploitation


class TestingPhase(Enum):
    """VAPT lifecycle phases"""
    RECONNAISSANCE = "reconnaissance"
    DISCOVERY = "discovery"
    TARGETED_TESTING = "targeted_testing"
    REPORTING = "reporting"


@dataclass
class AuthorizationScope:
    """
    Defines the scope and boundaries of authorized testing.

    All targets must be explicitly listed and authorized.
    """
    target_domains: list[str] = field(default_factory=list)
    target_ips: list[str] = field(default_factory=list)
    target_endpoints: list[str] = field(default_factory=list)

    # Explicitly excluded resources (production databases, etc.)
    exclusions: list[str] = field(default_factory=list)

    # Authorization details
    authorization_document: Optional[str] = None  # Reference to written auth
    authorized_by: Optional[str] = None
    authorization_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None

    # Testing boundaries
    allowed_phases: list[TestingPhase] = field(default_factory=lambda: [
        TestingPhase.RECONNAISSANCE,
        TestingPhase.DISCOVERY,
        TestingPhase.REPORTING
    ])

    max_requests_per_second: int = 10  # Rate limiting
    allowed_ports: list[int] = field(default_factory=lambda: [80, 443, 8080, 8443])

    def is_target_authorized(self, target: str) -> bool:
        """Check if a specific target is within authorized scope"""
        # Check exclusions first
        for exclusion in self.exclusions:
            if exclusion in target:
                return False

        # Check if target matches authorized domains/IPs
        for domain in self.target_domains:
            if domain in target or target.endswith(domain):
                return True

        for ip in self.target_ips:
            if ip == target or target.startswith(ip):
                return True

        return False

    def is_expired(self) -> bool:
        """Check if authorization has expired"""
        if self.expiration_date is None:
            return False
        return datetime.now() > self.expiration_date

    def to_dict(self) -> dict:
        """Serialize scope for logging/audit"""
        return {
            "target_domains": self.target_domains,
            "target_ips": self.target_ips,
            "exclusions": self.exclusions,
            "authorization_document": self.authorization_document,
            "authorized_by": self.authorized_by,
            "authorization_date": self.authorization_date.isoformat() if self.authorization_date else None,
            "expiration_date": self.expiration_date.isoformat() if self.expiration_date else None,
            "allowed_phases": [p.value for p in self.allowed_phases],
            "max_requests_per_second": self.max_requests_per_second
        }


class AuthorizationManager:
    """
    Manages authorization state and enforces testing boundaries.

    CRITICAL: No active testing should proceed without proper authorization.
    """

    # Maximum number of audit log entries to prevent unbounded memory growth
    MAX_AUDIT_LOG_SIZE = 1000

    def __init__(self):
        self.current_level: AuthorizationLevel = AuthorizationLevel.NONE
        self.scope: Optional[AuthorizationScope] = None
        self.exploit_approval: bool = False
        self._audit_log: list[dict] = []

    def set_authorization(
        self,
        level: AuthorizationLevel,
        scope: AuthorizationScope,
        exploit_approval: bool = False
    ) -> bool:
        """
        Set authorization level and scope for testing session.

        Args:
            level: The authorization level for this session
            scope: The defined scope of authorized testing
            exploit_approval: Explicit flag for exploit testing (requires separate approval)

        Returns:
            bool: True if authorization was set successfully
        """
        # Validate scope
        if scope.is_expired():
            self._log_audit("authorization_rejected", "Scope has expired")
            return False

        if not scope.target_domains and not scope.target_ips:
            self._log_audit("authorization_rejected", "No targets defined in scope")
            return False

        # Exploit approval requires explicit flag AND document reference
        if level == AuthorizationLevel.EXPLOIT_APPROVAL:
            if not exploit_approval:
                self._log_audit("authorization_rejected",
                              "Exploit-level requires explicit exploit_approval flag")
                return False
            if not scope.authorization_document:
                self._log_audit("authorization_rejected",
                              "Exploit-level requires authorization document reference")
                return False

        self.current_level = level
        self.scope = scope
        self.exploit_approval = exploit_approval

        self._log_audit("authorization_granted", {
            "level": level.value,
            "scope": scope.to_dict(),
            "exploit_approval": exploit_approval
        })

        return True

    def check_authorization(
        self,
        target: str,
        phase: TestingPhase,
        requires_exploit: bool = False
    ) -> tuple[bool, str]:
        """
        Check if a specific action is authorized.

        Args:
            target: The target being tested
            phase: The testing phase
            requires_exploit: Whether this action requires exploit-level approval

        Returns:
            tuple: (is_authorized, reason)
        """
        if self.scope is None:
            return False, "No authorization scope configured"

        if self.scope.is_expired():
            return False, "Authorization has expired"

        if not self.scope.is_target_authorized(target):
            return False, f"Target '{target}' is not within authorized scope"

        if phase not in self.scope.allowed_phases:
            return False, f"Phase '{phase.value}' is not authorized"

        if requires_exploit and not self.exploit_approval:
            return False, "Action requires Exploit-Approval flag which is not set"

        if requires_exploit and self.current_level != AuthorizationLevel.EXPLOIT_APPROVAL:
            return False, "Action requires EXPLOIT_APPROVAL authorization level"

        return True, "Authorized"

    def _log_audit(self, event: str, details: any):
        """Log authorization events for audit trail with bounded size"""
        self._audit_log.append({
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "details": details
        })
        # Prevent unbounded memory growth by trimming old entries
        if len(self._audit_log) > self.MAX_AUDIT_LOG_SIZE:
            # Keep the most recent entries, removing oldest
            self._audit_log = self._audit_log[-self.MAX_AUDIT_LOG_SIZE:]

    def get_audit_log(self) -> list[dict]:
        """Return the audit log for this session"""
        return self._audit_log.copy()

    def revoke_authorization(self):
        """Revoke all current authorization"""
        self._log_audit("authorization_revoked", {
            "previous_level": self.current_level.value if self.current_level else None
        })
        self.current_level = AuthorizationLevel.NONE
        self.scope = None
        self.exploit_approval = False
