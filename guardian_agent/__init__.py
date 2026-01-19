"""
Guardian-Agent: A Claude Plugin for Authorized VAPT Testing

This plugin follows a strict Vulnerability Assessment & Penetration Testing (VAPT)
lifecycle with built-in safeguards and authorization controls.

IMPORTANT: This tool is designed for AUTHORIZED security testing only.
Always obtain proper written authorization before testing any system.
"""

__version__ = "1.0.0"
__author__ = "Security Assessment Team"

from .plugin import GuardianAgent
from .authorization import AuthorizationManager, AuthorizationScope

__all__ = ["GuardianAgent", "AuthorizationManager", "AuthorizationScope"]
