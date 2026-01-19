"""
Authorization Management for Guardian-Agent

Ensures all testing activities are properly authorized and scoped.
No testing can occur without explicit authorization.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
from pathlib import Path
from urllib.parse import urlparse
import hashlib
import ipaddress
import json
import re


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

    def is_target_authorized(self, target: str, endpoint: Optional[str] = None) -> bool:
        """
        Check if a specific target is within authorized scope.

        Uses proper domain boundary matching to prevent bypasses like
        evil-example.com matching authorized example.com.

        Args:
            target: The target domain, IP, or URL being tested
            endpoint: Optional specific endpoint being accessed

        Returns:
            bool: True if target is authorized
        """
        # Extract domain from URL if needed
        target_domain = self._extract_domain(target)

        # Check exclusions first with proper matching
        for exclusion in self.exclusions:
            if self._domain_matches(exclusion, target_domain):
                return False

        # Check if target matches authorized domains
        domain_authorized = False
        for domain in self.target_domains:
            if self._domain_matches(domain, target_domain):
                domain_authorized = True
                break

        # Check if target matches authorized IPs
        if not domain_authorized:
            for ip in self.target_ips:
                if self._ip_matches(ip, target_domain):
                    domain_authorized = True
                    break

        if not domain_authorized:
            return False

        # If endpoints are defined, validate endpoint access
        if endpoint and self.target_endpoints:
            endpoint_authorized = False
            for allowed_endpoint in self.target_endpoints:
                if self._endpoint_matches(allowed_endpoint, endpoint):
                    endpoint_authorized = True
                    break

            if not endpoint_authorized:
                return False

        return True

    def _extract_domain(self, target: str) -> str:
        """Extract domain/host from a URL or return as-is if already a domain/IP."""
        if '://' in target:
            parsed = urlparse(target)
            return parsed.netloc.lower() if parsed.netloc else target.lower()
        return target.lower()

    def _domain_matches(self, authorized: str, target: str) -> bool:
        """
        Properly match domains with boundary validation.

        Prevents bypass attacks where evil-example.com would match example.com.

        - example.com matches example.com (exact)
        - example.com matches sub.example.com (subdomain)
        - example.com does NOT match evil-example.com (boundary violation)
        - *.example.com matches any.sub.example.com (wildcard)
        """
        authorized = authorized.lower().strip()
        target = target.lower().strip()

        # Remove port if present
        if ':' in target:
            target = target.split(':')[0]

        # Handle wildcard patterns
        if authorized.startswith('*.'):
            base_domain = authorized[2:]  # Remove *.
            # Target must end with .base_domain (not just base_domain)
            return target == base_domain or target.endswith('.' + base_domain)

        # Exact match
        if target == authorized:
            return True

        # Subdomain match: target must end with ".authorized"
        # This prevents evil-example.com from matching example.com
        if target.endswith('.' + authorized):
            return True

        return False

    def _ip_matches(self, authorized: str, target: str) -> bool:
        """
        Properly match IP addresses with CIDR support.

        Prevents bypass attacks with improper prefix matching.

        - 192.168.1.1 matches 192.168.1.1 (exact)
        - 192.168.1.0/24 matches 192.168.1.50 (CIDR range)
        - 192.168.1 does NOT match 192.168.100.1 (no partial prefix)
        """
        # Remove port if present in target
        if ':' in target:
            target = target.split(':')[0]

        try:
            # Exact IP match
            if authorized == target:
                return True

            # CIDR range matching
            if '/' in authorized:
                network = ipaddress.ip_network(authorized, strict=False)
                addr = ipaddress.ip_address(target)
                return addr in network

            # Validate both are proper IPs before any comparison
            ipaddress.ip_address(authorized)
            ipaddress.ip_address(target)

            return authorized == target

        except ValueError:
            # Not valid IP addresses
            return False

    def _endpoint_matches(self, authorized: str, target: str) -> bool:
        """
        Match endpoints with proper path boundary validation.

        - /api/users matches /api/users (exact)
        - /api/users matches /api/users/123 (prefix with boundary)
        - /api does NOT match /api-v2 (boundary violation)
        """
        authorized = authorized.rstrip('/')
        target = target.rstrip('/')

        # Exact match
        if target == authorized:
            return True

        # Prefix match with path boundary
        if target.startswith(authorized + '/'):
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

    Features:
    - Persistent audit logging with file-based storage
    - Tamper detection via hash chaining
    - Proper domain/IP boundary matching
    - Endpoint-level authorization
    """

    def __init__(self, audit_log_path: Optional[str] = None):
        """
        Initialize the authorization manager.

        Args:
            audit_log_path: Optional path for persistent audit log storage.
                           If provided, all audit events are written to this file.
        """
        self.current_level: AuthorizationLevel = AuthorizationLevel.NONE
        self.scope: Optional[AuthorizationScope] = None
        self.exploit_approval: bool = False
        self._audit_log: list[dict] = []
        self._audit_log_path = Path(audit_log_path) if audit_log_path else None
        self._previous_hash = "initial"  # For tamper detection chain

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
        requires_exploit: bool = False,
        endpoint: Optional[str] = None
    ) -> tuple[bool, str]:
        """
        Check if a specific action is authorized.

        Args:
            target: The target being tested
            phase: The testing phase
            requires_exploit: Whether this action requires exploit-level approval
            endpoint: Optional specific endpoint being accessed

        Returns:
            tuple: (is_authorized, reason)
        """
        if self.scope is None:
            self._log_audit("authorization_check_failed", {
                "target": target,
                "reason": "No authorization scope configured"
            })
            return False, "No authorization scope configured"

        if self.scope.is_expired():
            self._log_audit("authorization_check_failed", {
                "target": target,
                "reason": "Authorization has expired"
            })
            return False, "Authorization has expired"

        if not self.scope.is_target_authorized(target, endpoint):
            reason = f"Target '{target}' is not within authorized scope"
            if endpoint:
                reason += f" (endpoint: {endpoint})"
            self._log_audit("authorization_check_failed", {
                "target": target,
                "endpoint": endpoint,
                "reason": reason
            })
            return False, reason

        if phase not in self.scope.allowed_phases:
            self._log_audit("authorization_check_failed", {
                "target": target,
                "phase": phase.value,
                "reason": "Phase not authorized"
            })
            return False, f"Phase '{phase.value}' is not authorized"

        if requires_exploit and not self.exploit_approval:
            self._log_audit("authorization_check_failed", {
                "target": target,
                "reason": "Exploit approval flag not set"
            })
            return False, "Action requires Exploit-Approval flag which is not set"

        if requires_exploit and self.current_level != AuthorizationLevel.EXPLOIT_APPROVAL:
            self._log_audit("authorization_check_failed", {
                "target": target,
                "reason": "Insufficient authorization level"
            })
            return False, "Action requires EXPLOIT_APPROVAL authorization level"

        self._log_audit("authorization_check_passed", {
            "target": target,
            "phase": phase.value,
            "endpoint": endpoint,
            "requires_exploit": requires_exploit
        })
        return True, "Authorized"

    def _log_audit(self, event: str, details: dict):
        """
        Log authorization events with tamper detection.

        Creates a hash chain where each entry includes the hash of the
        previous entry, making tampering detectable.

        Args:
            event: The type of event being logged
            details: Dictionary of event details (must be JSON-serializable)
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "details": details if isinstance(details, dict) else {"message": str(details)},
            "previous_hash": self._previous_hash
        }

        # Calculate hash for this entry (includes previous hash for chaining)
        entry_json = json.dumps(entry, sort_keys=True)
        entry_hash = hashlib.sha256(entry_json.encode()).hexdigest()
        entry["hash"] = entry_hash
        self._previous_hash = entry_hash

        self._audit_log.append(entry)

        # Persist to file if configured
        if self._audit_log_path:
            try:
                with open(self._audit_log_path, 'a') as f:
                    f.write(json.dumps(entry) + '\n')
            except IOError:
                # Don't fail the operation if audit logging fails
                pass

    def get_audit_log(self) -> list[dict]:
        """Return the audit log for this session"""
        return self._audit_log.copy()

    def verify_audit_log_integrity(self) -> tuple[bool, Optional[str]]:
        """
        Verify the audit log hasn't been tampered with.

        Validates the hash chain from beginning to end.

        Returns:
            tuple: (is_valid, error_message if invalid)
        """
        if not self._audit_log:
            return True, None

        previous_hash = "initial"

        for i, entry in enumerate(self._audit_log):
            stored_hash = entry.get("hash")
            if not stored_hash:
                return False, f"Entry {i} missing hash"

            # Reconstruct expected hash
            entry_copy = {
                "timestamp": entry["timestamp"],
                "event": entry["event"],
                "details": entry["details"],
                "previous_hash": previous_hash
            }
            entry_json = json.dumps(entry_copy, sort_keys=True)
            expected_hash = hashlib.sha256(entry_json.encode()).hexdigest()

            if expected_hash != stored_hash:
                return False, f"Entry {i} hash mismatch - possible tampering"

            previous_hash = stored_hash

        return True, None

    def load_audit_log(self, path: Optional[str] = None) -> bool:
        """
        Load audit log from file and verify integrity.

        Args:
            path: Path to audit log file. Uses configured path if not provided.

        Returns:
            bool: True if loaded and verified successfully
        """
        log_path = Path(path) if path else self._audit_log_path
        if not log_path or not log_path.exists():
            return False

        try:
            entries = []
            with open(log_path, 'r') as f:
                for line in f:
                    if line.strip():
                        entries.append(json.loads(line))

            # Temporarily store and verify
            old_log = self._audit_log
            self._audit_log = entries

            valid, error = self.verify_audit_log_integrity()
            if not valid:
                self._audit_log = old_log
                return False

            # Update hash chain state
            if entries:
                self._previous_hash = entries[-1].get("hash", "initial")

            return True
        except (IOError, json.JSONDecodeError):
            return False

    def revoke_authorization(self):
        """Revoke all current authorization"""
        self._log_audit("authorization_revoked", {
            "previous_level": self.current_level.value if self.current_level else None
        })
        self.current_level = AuthorizationLevel.NONE
        self.scope = None
        self.exploit_approval = False
