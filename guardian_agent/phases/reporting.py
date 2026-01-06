"""
Phase 4: Reporting

Generates comprehensive security assessment reports with findings,
severity ratings, impact analysis, and remediation guidance.

Report format follows industry standards (OWASP, CVSS).
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import json
import hashlib

from ..authorization import AuthorizationManager, AuthorizationScope
from .reconnaissance import TechFingerprint
from .discovery import DiscoveryResults
from .targeted_testing import TestResult, Severity


class ReportFormat(Enum):
    """Supported report output formats"""
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"


class ImpactCategory(Enum):
    """Impact categories for findings"""
    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    AVAILABILITY = "availability"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"


@dataclass
class Finding:
    """
    Represents a security finding with full context.

    Follows OWASP and industry-standard reporting conventions.
    """
    id: str
    title: str
    severity: Severity
    description: str
    impact: str
    impact_categories: list[ImpactCategory]
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    affected_component: str = ""
    affected_endpoints: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    steps_to_reproduce: list[str] = field(default_factory=list)
    remediation: str = ""
    remediation_effort: str = ""  # Low, Medium, High
    references: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    owasp_category: Optional[str] = None
    discovered_at: datetime = field(default_factory=datetime.now)
    was_safe_check: bool = True

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "description": self.description,
            "impact": self.impact,
            "impact_categories": [ic.value for ic in self.impact_categories],
            "affected_component": self.affected_component,
            "affected_endpoints": self.affected_endpoints,
            "evidence": self.evidence,
            "steps_to_reproduce": self.steps_to_reproduce,
            "remediation": {
                "description": self.remediation,
                "effort": self.remediation_effort
            },
            "references": self.references,
            "cwe_ids": self.cwe_ids,
            "owasp_category": self.owasp_category,
            "discovered_at": self.discovered_at.isoformat(),
            "testing_method": "safe_check" if self.was_safe_check else "active_test"
        }


@dataclass
class SecurityReport:
    """
    Complete security assessment report.
    """
    report_id: str
    title: str
    target: str
    scope: dict
    executive_summary: str
    methodology: str
    findings: list[Finding] = field(default_factory=list)
    tech_fingerprint: Optional[dict] = None
    discovery_summary: Optional[dict] = None
    testing_summary: dict = field(default_factory=dict)
    recommendations: list[dict] = field(default_factory=list)
    generated_at: datetime = field(default_factory=datetime.now)
    assessment_period: dict = field(default_factory=dict)
    assessor: str = "Guardian-Agent Automated Scanner"
    version: str = "1.0"

    def to_dict(self) -> dict:
        return {
            "metadata": {
                "report_id": self.report_id,
                "title": self.title,
                "version": self.version,
                "generated_at": self.generated_at.isoformat(),
                "assessor": self.assessor,
                "assessment_period": self.assessment_period
            },
            "target": self.target,
            "scope": self.scope,
            "executive_summary": self.executive_summary,
            "methodology": self.methodology,
            "tech_fingerprint": self.tech_fingerprint,
            "discovery_summary": self.discovery_summary,
            "findings": {
                "total": len(self.findings),
                "by_severity": self._count_by_severity(),
                "items": [f.to_dict() for f in self.findings]
            },
            "testing_summary": self.testing_summary,
            "recommendations": self.recommendations
        }

    def _count_by_severity(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts


class ReportingPhase:
    """
    Phase 4: Security Report Generation

    Compiles all findings into comprehensive, actionable reports.
    """

    # JSON Schema for report validation
    REPORT_SCHEMA = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Guardian-Agent Security Report",
        "type": "object",
        "required": ["metadata", "target", "scope", "findings"],
        "properties": {
            "metadata": {
                "type": "object",
                "required": ["report_id", "title", "generated_at"],
                "properties": {
                    "report_id": {"type": "string", "pattern": "^GAR-[0-9]{8}-[A-Z0-9]{6}$"},
                    "title": {"type": "string", "minLength": 10},
                    "version": {"type": "string"},
                    "generated_at": {"type": "string", "format": "date-time"},
                    "assessor": {"type": "string"},
                    "assessment_period": {
                        "type": "object",
                        "properties": {
                            "start": {"type": "string", "format": "date-time"},
                            "end": {"type": "string", "format": "date-time"}
                        }
                    }
                }
            },
            "target": {"type": "string", "format": "uri"},
            "scope": {
                "type": "object",
                "required": ["authorized_targets", "exclusions"],
                "properties": {
                    "authorized_targets": {"type": "array", "items": {"type": "string"}},
                    "exclusions": {"type": "array", "items": {"type": "string"}},
                    "authorization_reference": {"type": "string"},
                    "testing_limitations": {"type": "array", "items": {"type": "string"}}
                }
            },
            "executive_summary": {"type": "string", "minLength": 100},
            "methodology": {"type": "string"},
            "tech_fingerprint": {
                "type": "object",
                "properties": {
                    "databases": {"type": "array", "items": {"type": "string"}},
                    "frameworks": {"type": "array", "items": {"type": "string"}},
                    "cloud_services": {"type": "array", "items": {"type": "string"}},
                    "confidence_scores": {"type": "object"}
                }
            },
            "discovery_summary": {
                "type": "object",
                "properties": {
                    "total_endpoints": {"type": "integer"},
                    "authenticated_endpoints": {"type": "integer"},
                    "endpoint_types": {"type": "object"}
                }
            },
            "findings": {
                "type": "object",
                "required": ["total", "by_severity", "items"],
                "properties": {
                    "total": {"type": "integer", "minimum": 0},
                    "by_severity": {
                        "type": "object",
                        "properties": {
                            "critical": {"type": "integer"},
                            "high": {"type": "integer"},
                            "medium": {"type": "integer"},
                            "low": {"type": "integer"},
                            "info": {"type": "integer"}
                        }
                    },
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["id", "title", "severity", "description", "remediation"],
                            "properties": {
                                "id": {"type": "string"},
                                "title": {"type": "string"},
                                "severity": {
                                    "type": "string",
                                    "enum": ["critical", "high", "medium", "low", "info"]
                                },
                                "cvss_score": {"type": "number", "minimum": 0, "maximum": 10},
                                "cvss_vector": {"type": "string"},
                                "description": {"type": "string"},
                                "impact": {"type": "string"},
                                "impact_categories": {
                                    "type": "array",
                                    "items": {
                                        "type": "string",
                                        "enum": ["confidentiality", "integrity", "availability",
                                                "authentication", "authorization"]
                                    }
                                },
                                "affected_component": {"type": "string"},
                                "affected_endpoints": {"type": "array", "items": {"type": "string"}},
                                "evidence": {"type": "array", "items": {"type": "string"}},
                                "steps_to_reproduce": {"type": "array", "items": {"type": "string"}},
                                "remediation": {
                                    "type": "object",
                                    "required": ["description"],
                                    "properties": {
                                        "description": {"type": "string"},
                                        "effort": {
                                            "type": "string",
                                            "enum": ["low", "medium", "high"]
                                        }
                                    }
                                },
                                "references": {"type": "array", "items": {"type": "string"}},
                                "cwe_ids": {"type": "array", "items": {"type": "string"}},
                                "owasp_category": {"type": "string"},
                                "discovered_at": {"type": "string", "format": "date-time"},
                                "testing_method": {
                                    "type": "string",
                                    "enum": ["safe_check", "active_test"]
                                }
                            }
                        }
                    }
                }
            },
            "testing_summary": {
                "type": "object",
                "properties": {
                    "total_tests_executed": {"type": "integer"},
                    "safe_checks_count": {"type": "integer"},
                    "active_tests_count": {"type": "integer"},
                    "tests_passed": {"type": "integer"},
                    "tests_failed": {"type": "integer"},
                    "exploit_approval_used": {"type": "boolean"}
                }
            },
            "recommendations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["priority", "title", "description"],
                    "properties": {
                        "priority": {"type": "integer", "minimum": 1, "maximum": 10},
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "related_findings": {"type": "array", "items": {"type": "string"}},
                        "effort_estimate": {"type": "string"}
                    }
                }
            }
        }
    }

    # Finding templates for common vulnerabilities
    FINDING_TEMPLATES = {
        "SUP-001": {
            "title": "Supabase Row Level Security (RLS) Policy Misconfiguration",
            "impact": "Unauthorized users may access, modify, or delete data belonging to other users",
            "impact_categories": [ImpactCategory.CONFIDENTIALITY, ImpactCategory.INTEGRITY],
            "cvss_score": 9.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cwe_ids": ["CWE-284", "CWE-862"],
            "owasp_category": "A01:2021 – Broken Access Control",
            "references": [
                "https://supabase.com/docs/guides/auth/row-level-security",
                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
            ],
            "remediation_effort": "medium"
        },
        "MDB-001": {
            "title": "MongoDB NoSQL Injection via Operator Injection",
            "impact": "Attackers can bypass authentication, extract sensitive data, or modify queries",
            "impact_categories": [ImpactCategory.CONFIDENTIALITY, ImpactCategory.AUTHENTICATION],
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe_ids": ["CWE-943", "CWE-89"],
            "owasp_category": "A03:2021 – Injection",
            "references": [
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html"
            ],
            "remediation_effort": "medium"
        },
        "PG-001": {
            "title": "SQL Injection Vulnerability",
            "impact": "Attackers can read, modify, or delete database contents, potentially gaining system access",
            "impact_categories": [ImpactCategory.CONFIDENTIALITY, ImpactCategory.INTEGRITY, ImpactCategory.AVAILABILITY],
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe_ids": ["CWE-89"],
            "owasp_category": "A03:2021 – Injection",
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ],
            "remediation_effort": "medium"
        },
        "API-001": {
            "title": "Broken Object Level Authorization (BOLA/IDOR)",
            "impact": "Attackers can access or modify resources belonging to other users",
            "impact_categories": [ImpactCategory.CONFIDENTIALITY, ImpactCategory.INTEGRITY, ImpactCategory.AUTHORIZATION],
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cwe_ids": ["CWE-639", "CWE-284"],
            "owasp_category": "A01:2021 – Broken Access Control",
            "references": [
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
            ],
            "remediation_effort": "high"
        },
        "AUTH-001": {
            "title": "JWT Algorithm Confusion Vulnerability",
            "impact": "Attackers can forge authentication tokens and impersonate any user",
            "impact_categories": [ImpactCategory.AUTHENTICATION, ImpactCategory.AUTHORIZATION],
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "cwe_ids": ["CWE-327", "CWE-347"],
            "owasp_category": "A02:2021 – Cryptographic Failures",
            "references": [
                "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                "https://portswigger.net/web-security/jwt/algorithm-confusion"
            ],
            "remediation_effort": "low"
        }
    }

    def __init__(self, auth_manager: AuthorizationManager):
        self.auth_manager = auth_manager

    def generate_report_id(self) -> str:
        """Generate a unique report ID"""
        timestamp = datetime.now().strftime("%Y%m%d")
        hash_suffix = hashlib.sha256(
            f"{timestamp}{datetime.now().timestamp()}".encode()
        ).hexdigest()[:6].upper()
        return f"GAR-{timestamp}-{hash_suffix}"

    def create_finding_from_test_result(
        self,
        test_result: TestResult,
        affected_endpoints: list[str]
    ) -> Optional[Finding]:
        """
        Create a Finding from a TestResult.

        Args:
            test_result: Result from targeted testing
            affected_endpoints: List of affected endpoints

        Returns:
            Finding object or None if not vulnerable
        """
        if not test_result.vulnerable:
            return None

        test_id = test_result.test_case.id
        template = self.FINDING_TEMPLATES.get(test_id, {})

        finding_id = f"F-{test_id}-{datetime.now().strftime('%H%M%S')}"

        return Finding(
            id=finding_id,
            title=template.get("title", test_result.test_case.name),
            severity=test_result.test_case.severity_if_vulnerable,
            description=test_result.test_case.description,
            impact=template.get("impact", "Security impact requires further analysis"),
            impact_categories=template.get("impact_categories", [ImpactCategory.CONFIDENTIALITY]),
            cvss_score=template.get("cvss_score"),
            cvss_vector=template.get("cvss_vector"),
            affected_endpoints=affected_endpoints,
            evidence=test_result.evidence,
            remediation=test_result.test_case.remediation,
            remediation_effort=template.get("remediation_effort", "medium"),
            references=template.get("references", []),
            cwe_ids=template.get("cwe_ids", []),
            owasp_category=template.get("owasp_category"),
            was_safe_check=test_result.was_safe_check
        )

    def generate_executive_summary(
        self,
        findings: list[Finding],
        target: str
    ) -> str:
        """
        Generate an executive summary for the report.

        Args:
            findings: List of findings
            target: Target assessed

        Returns:
            Executive summary text
        """
        severity_counts = {s: 0 for s in Severity}
        for f in findings:
            severity_counts[f.severity] += 1

        critical_high = severity_counts[Severity.CRITICAL] + severity_counts[Severity.HIGH]

        if critical_high == 0:
            risk_assessment = "LOW"
            risk_description = "No critical or high severity vulnerabilities were identified."
        elif severity_counts[Severity.CRITICAL] > 0:
            risk_assessment = "CRITICAL"
            risk_description = f"Critical vulnerabilities were identified that require immediate attention."
        else:
            risk_assessment = "HIGH"
            risk_description = "High severity vulnerabilities were identified that should be addressed promptly."

        summary = f"""SECURITY ASSESSMENT EXECUTIVE SUMMARY
=====================================

Target: {target}
Assessment Date: {datetime.now().strftime('%Y-%m-%d')}
Overall Risk Level: {risk_assessment}

FINDINGS SUMMARY
----------------
- Critical: {severity_counts[Severity.CRITICAL]}
- High: {severity_counts[Severity.HIGH]}
- Medium: {severity_counts[Severity.MEDIUM]}
- Low: {severity_counts[Severity.LOW]}
- Informational: {severity_counts[Severity.INFO]}
- Total: {len(findings)}

RISK ASSESSMENT
---------------
{risk_description}

"""
        if severity_counts[Severity.CRITICAL] > 0:
            summary += """IMMEDIATE ACTIONS REQUIRED
--------------------------
Critical vulnerabilities require immediate remediation. These issues may allow
unauthorized access to sensitive data or system compromise.

"""

        return summary

    def generate_recommendations(self, findings: list[Finding]) -> list[dict]:
        """
        Generate prioritized recommendations based on findings.

        Args:
            findings: List of findings

        Returns:
            List of prioritized recommendations
        """
        recommendations = []
        priority = 1

        # Group findings by severity
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        high_findings = [f for f in findings if f.severity == Severity.HIGH]
        medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]

        if critical_findings:
            recommendations.append({
                "priority": priority,
                "title": "Immediate: Address Critical Vulnerabilities",
                "description": "Critical vulnerabilities pose an immediate risk and should be "
                              "remediated within 24-48 hours. These may allow unauthorized "
                              "data access or system compromise.",
                "related_findings": [f.id for f in critical_findings],
                "effort_estimate": "Varies by finding"
            })
            priority += 1

        if high_findings:
            recommendations.append({
                "priority": priority,
                "title": "Short-term: Remediate High Severity Issues",
                "description": "High severity issues should be addressed within 1-2 weeks. "
                              "These vulnerabilities could be exploited to access sensitive data.",
                "related_findings": [f.id for f in high_findings],
                "effort_estimate": "Varies by finding"
            })
            priority += 1

        if medium_findings:
            recommendations.append({
                "priority": priority,
                "title": "Medium-term: Address Medium Severity Findings",
                "description": "Medium severity findings should be incorporated into the "
                              "regular development cycle and addressed within 30 days.",
                "related_findings": [f.id for f in medium_findings],
                "effort_estimate": "Varies by finding"
            })
            priority += 1

        # Add general recommendations
        recommendations.extend([
            {
                "priority": priority,
                "title": "Implement Security Testing in CI/CD",
                "description": "Integrate automated security testing into the development "
                              "pipeline to catch vulnerabilities early.",
                "related_findings": [],
                "effort_estimate": "Medium"
            },
            {
                "priority": priority + 1,
                "title": "Conduct Regular Security Assessments",
                "description": "Schedule periodic security assessments to identify new "
                              "vulnerabilities as the application evolves.",
                "related_findings": [],
                "effort_estimate": "Ongoing"
            }
        ])

        return recommendations

    def generate_report(
        self,
        target: str,
        scope: AuthorizationScope,
        fingerprint: Optional[TechFingerprint],
        discovery_results: Optional[DiscoveryResults],
        test_results: list[TestResult],
        title: Optional[str] = None
    ) -> SecurityReport:
        """
        Generate a complete security report.

        Args:
            target: Target assessed
            scope: Authorization scope
            fingerprint: Technology fingerprint
            discovery_results: Discovery phase results
            test_results: Targeted testing results
            title: Optional custom report title

        Returns:
            Complete SecurityReport
        """
        # Create findings from test results
        findings = []
        for result in test_results:
            finding = self.create_finding_from_test_result(
                result,
                affected_endpoints=discovery_results.endpoints if discovery_results else []
            )
            if finding:
                findings.append(finding)

        # Sort findings by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        findings.sort(key=lambda f: severity_order[f.severity])

        # Generate report components
        report = SecurityReport(
            report_id=self.generate_report_id(),
            title=title or f"Security Assessment Report - {target}",
            target=target,
            scope={
                "authorized_targets": scope.target_domains + scope.target_ips,
                "exclusions": scope.exclusions,
                "authorization_reference": scope.authorization_document,
                "testing_limitations": [
                    "Testing limited to authorized scope",
                    "No destructive tests performed" if not self.auth_manager.exploit_approval
                    else "Active testing performed with approval"
                ]
            },
            executive_summary=self.generate_executive_summary(findings, target),
            methodology=self._get_methodology_text(),
            findings=findings,
            tech_fingerprint=fingerprint.to_dict() if fingerprint else None,
            discovery_summary={
                "total_endpoints": len(discovery_results.endpoints) if discovery_results else 0,
                "endpoint_types": {}
            } if discovery_results else None,
            testing_summary={
                "total_tests_executed": len(test_results),
                "safe_checks_count": sum(1 for r in test_results if r.was_safe_check),
                "active_tests_count": sum(1 for r in test_results if not r.was_safe_check),
                "vulnerabilities_found": len(findings),
                "exploit_approval_used": self.auth_manager.exploit_approval
            },
            recommendations=self.generate_recommendations(findings)
        )

        return report

    def _get_methodology_text(self) -> str:
        """Return standard methodology description"""
        return """This assessment followed the Guardian-Agent VAPT methodology:

1. RECONNAISSANCE: Passive information gathering and technology fingerprinting
   to identify the target's technology stack.

2. DISCOVERY: Endpoint enumeration and attack surface mapping using
   directory brute-forcing and API endpoint discovery.

3. TARGETED TESTING: Vulnerability testing tailored to the detected
   technology stack. Safe-Checks were prioritized, with active testing
   only performed when explicitly authorized.

4. REPORTING: Comprehensive documentation of findings with severity
   ratings, impact analysis, and remediation guidance.

All testing was conducted within the authorized scope and with appropriate
rate limiting to prevent service disruption."""

    def export_report(
        self,
        report: SecurityReport,
        format: ReportFormat = ReportFormat.JSON
    ) -> str:
        """
        Export report to specified format.

        Args:
            report: SecurityReport to export
            format: Output format

        Returns:
            Formatted report string
        """
        if format == ReportFormat.JSON:
            return json.dumps(report.to_dict(), indent=2, default=str)

        elif format == ReportFormat.MARKDOWN:
            return self._to_markdown(report)

        elif format == ReportFormat.HTML:
            return self._to_html(report)

        return json.dumps(report.to_dict(), indent=2, default=str)

    def _to_markdown(self, report: SecurityReport) -> str:
        """Convert report to Markdown format"""
        md = f"""# {report.title}

**Report ID:** {report.report_id}
**Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}
**Target:** {report.target}

---

## Executive Summary

{report.executive_summary}

---

## Scope

**Authorized Targets:**
{chr(10).join('- ' + t for t in report.scope.get('authorized_targets', []))}

**Exclusions:**
{chr(10).join('- ' + e for e in report.scope.get('exclusions', [])) or '- None'}

---

## Findings

"""
        for finding in report.findings:
            md += f"""### [{finding.severity.value.upper()}] {finding.title}

**ID:** {finding.id}
**CVSS Score:** {finding.cvss_score or 'N/A'}

**Description:**
{finding.description}

**Impact:**
{finding.impact}

**Remediation:**
{finding.remediation}

**References:**
{chr(10).join('- ' + r for r in finding.references) or '- None'}

---

"""

        md += """## Recommendations

"""
        for rec in report.recommendations:
            md += f"""### Priority {rec['priority']}: {rec['title']}

{rec['description']}

"""

        return md

    def _to_html(self, report: SecurityReport) -> str:
        """Convert report to HTML format"""
        # Basic HTML template - in production would use proper templating
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>{report.title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        .info {{ color: #1976d2; }}
        .finding {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; }}
    </style>
</head>
<body>
    <h1>{report.title}</h1>
    <p><strong>Report ID:</strong> {report.report_id}</p>
    <p><strong>Target:</strong> {report.target}</p>

    <h2>Executive Summary</h2>
    <pre>{report.executive_summary}</pre>

    <h2>Findings ({len(report.findings)} total)</h2>
    {''.join(f'''
    <div class="finding">
        <h3 class="{f.severity.value}">[{f.severity.value.upper()}] {f.title}</h3>
        <p><strong>Description:</strong> {f.description}</p>
        <p><strong>Impact:</strong> {f.impact}</p>
        <p><strong>Remediation:</strong> {f.remediation}</p>
    </div>
    ''' for f in report.findings)}

</body>
</html>"""

    def get_json_schema(self) -> dict:
        """Return the JSON schema for report validation"""
        return self.REPORT_SCHEMA
