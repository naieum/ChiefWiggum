"""
JSON Schema Definitions for Guardian-Agent Reports

These schemas define the structure and validation rules for security
assessment reports, ensuring consistent and complete documentation.
"""

import json
from typing import Optional

# Finding schema - individual vulnerability finding
FINDING_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "https://guardian-agent.security/schemas/finding.json",
    "title": "Security Finding",
    "description": "A single security finding from the assessment",
    "type": "object",
    "required": ["id", "title", "severity", "description", "remediation"],
    "properties": {
        "id": {
            "type": "string",
            "description": "Unique identifier for the finding",
            "pattern": "^F-[A-Z]{2,4}-[0-9]{3}-[0-9]{6}$",
            "examples": ["F-SUP-001-143052"]
        },
        "title": {
            "type": "string",
            "description": "Brief descriptive title of the vulnerability",
            "minLength": 10,
            "maxLength": 200
        },
        "severity": {
            "type": "string",
            "description": "Severity rating based on impact and exploitability",
            "enum": ["critical", "high", "medium", "low", "info"]
        },
        "cvss_score": {
            "type": "number",
            "description": "CVSS 3.1 base score",
            "minimum": 0.0,
            "maximum": 10.0
        },
        "cvss_vector": {
            "type": "string",
            "description": "CVSS 3.1 vector string",
            "pattern": "^CVSS:3\\.[01]/.*$",
            "examples": ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"]
        },
        "description": {
            "type": "string",
            "description": "Detailed description of the vulnerability",
            "minLength": 50
        },
        "impact": {
            "type": "string",
            "description": "Business and technical impact of exploitation"
        },
        "impact_categories": {
            "type": "array",
            "description": "CIA triad and access control impact categories",
            "items": {
                "type": "string",
                "enum": ["confidentiality", "integrity", "availability",
                        "authentication", "authorization"]
            },
            "uniqueItems": True
        },
        "affected_component": {
            "type": "string",
            "description": "The specific component or module affected"
        },
        "affected_endpoints": {
            "type": "array",
            "description": "List of affected API endpoints or URLs",
            "items": {"type": "string"}
        },
        "evidence": {
            "type": "array",
            "description": "Evidence supporting the finding",
            "items": {"type": "string"}
        },
        "steps_to_reproduce": {
            "type": "array",
            "description": "Step-by-step reproduction instructions",
            "items": {"type": "string"}
        },
        "remediation": {
            "type": "object",
            "description": "Remediation guidance",
            "required": ["description"],
            "properties": {
                "description": {
                    "type": "string",
                    "description": "Detailed remediation steps"
                },
                "effort": {
                    "type": "string",
                    "description": "Estimated remediation effort",
                    "enum": ["low", "medium", "high"]
                },
                "code_example": {
                    "type": "string",
                    "description": "Example code for fixing the issue"
                }
            }
        },
        "references": {
            "type": "array",
            "description": "External references (documentation, advisories)",
            "items": {
                "type": "string",
                "format": "uri"
            }
        },
        "cwe_ids": {
            "type": "array",
            "description": "Related CWE identifiers",
            "items": {
                "type": "string",
                "pattern": "^CWE-[0-9]+$"
            }
        },
        "owasp_category": {
            "type": "string",
            "description": "OWASP Top 10 category",
            "examples": ["A01:2021 – Broken Access Control"]
        },
        "discovered_at": {
            "type": "string",
            "description": "ISO 8601 timestamp of discovery",
            "format": "date-time"
        },
        "testing_method": {
            "type": "string",
            "description": "Method used to discover the vulnerability",
            "enum": ["safe_check", "active_test"]
        }
    }
}

# Complete report schema
REPORT_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "https://guardian-agent.security/schemas/report.json",
    "title": "Guardian-Agent Security Assessment Report",
    "description": "Complete security assessment report following VAPT methodology",
    "type": "object",
    "required": ["metadata", "target", "scope", "executive_summary", "findings"],
    "properties": {
        "metadata": {
            "type": "object",
            "description": "Report metadata",
            "required": ["report_id", "title", "generated_at"],
            "properties": {
                "report_id": {
                    "type": "string",
                    "description": "Unique report identifier",
                    "pattern": "^GAR-[0-9]{8}-[A-Z0-9]{6}$",
                    "examples": ["GAR-20241215-A1B2C3"]
                },
                "title": {
                    "type": "string",
                    "description": "Report title",
                    "minLength": 10
                },
                "version": {
                    "type": "string",
                    "description": "Report version",
                    "default": "1.0"
                },
                "generated_at": {
                    "type": "string",
                    "description": "Report generation timestamp",
                    "format": "date-time"
                },
                "assessor": {
                    "type": "string",
                    "description": "Assessment performed by",
                    "default": "Guardian-Agent Automated Scanner"
                },
                "assessment_period": {
                    "type": "object",
                    "description": "Assessment time period",
                    "properties": {
                        "start": {
                            "type": "string",
                            "format": "date-time"
                        },
                        "end": {
                            "type": "string",
                            "format": "date-time"
                        }
                    }
                }
            }
        },
        "target": {
            "type": "string",
            "description": "Primary target URL or system",
            "format": "uri"
        },
        "scope": {
            "type": "object",
            "description": "Assessment scope and boundaries",
            "required": ["authorized_targets"],
            "properties": {
                "authorized_targets": {
                    "type": "array",
                    "description": "List of authorized targets",
                    "items": {"type": "string"},
                    "minItems": 1
                },
                "exclusions": {
                    "type": "array",
                    "description": "Explicitly excluded resources",
                    "items": {"type": "string"}
                },
                "authorization_reference": {
                    "type": "string",
                    "description": "Reference to written authorization document"
                },
                "testing_limitations": {
                    "type": "array",
                    "description": "Any limitations on testing performed",
                    "items": {"type": "string"}
                }
            }
        },
        "executive_summary": {
            "type": "string",
            "description": "High-level summary for executive stakeholders",
            "minLength": 100
        },
        "methodology": {
            "type": "string",
            "description": "Description of testing methodology used"
        },
        "tech_fingerprint": {
            "type": "object",
            "description": "Detected technology stack",
            "properties": {
                "databases": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "frameworks": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "cloud_services": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "auth_providers": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "confidence_scores": {
                    "type": "object",
                    "additionalProperties": {"type": "number"}
                }
            }
        },
        "discovery_summary": {
            "type": "object",
            "description": "Summary of endpoint discovery",
            "properties": {
                "total_endpoints": {
                    "type": "integer",
                    "minimum": 0
                },
                "authenticated_endpoints": {
                    "type": "integer",
                    "minimum": 0
                },
                "endpoint_types": {
                    "type": "object",
                    "additionalProperties": {"type": "integer"}
                }
            }
        },
        "findings": {
            "type": "object",
            "description": "Security findings",
            "required": ["total", "by_severity", "items"],
            "properties": {
                "total": {
                    "type": "integer",
                    "description": "Total number of findings",
                    "minimum": 0
                },
                "by_severity": {
                    "type": "object",
                    "description": "Count of findings by severity",
                    "properties": {
                        "critical": {"type": "integer", "minimum": 0},
                        "high": {"type": "integer", "minimum": 0},
                        "medium": {"type": "integer", "minimum": 0},
                        "low": {"type": "integer", "minimum": 0},
                        "info": {"type": "integer", "minimum": 0}
                    }
                },
                "items": {
                    "type": "array",
                    "description": "List of findings",
                    "items": {"$ref": "#/$defs/finding"}
                }
            }
        },
        "testing_summary": {
            "type": "object",
            "description": "Summary of testing performed",
            "properties": {
                "total_tests_executed": {
                    "type": "integer",
                    "minimum": 0
                },
                "safe_checks_count": {
                    "type": "integer",
                    "minimum": 0
                },
                "active_tests_count": {
                    "type": "integer",
                    "minimum": 0
                },
                "vulnerabilities_found": {
                    "type": "integer",
                    "minimum": 0
                },
                "exploit_approval_used": {
                    "type": "boolean"
                }
            }
        },
        "recommendations": {
            "type": "array",
            "description": "Prioritized recommendations",
            "items": {
                "type": "object",
                "required": ["priority", "title", "description"],
                "properties": {
                    "priority": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 10
                    },
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "related_findings": {
                        "type": "array",
                        "items": {"type": "string"}
                    },
                    "effort_estimate": {"type": "string"}
                }
            }
        }
    },
    "$defs": {
        "finding": FINDING_SCHEMA
    }
}


def validate_report(report_data: dict) -> tuple[bool, Optional[list[str]]]:
    """
    Validate a report against the schema.

    Args:
        report_data: Report data dictionary

    Returns:
        tuple: (is_valid, list of errors or None)

    Note:
        This is a simplified validator. In production, use
        jsonschema library for full validation.
    """
    errors = []

    # Check required fields
    required_fields = ["metadata", "target", "scope", "executive_summary", "findings"]
    for field in required_fields:
        if field not in report_data:
            errors.append(f"Missing required field: {field}")

    # Validate metadata
    if "metadata" in report_data:
        metadata = report_data["metadata"]
        if "report_id" not in metadata:
            errors.append("Missing metadata.report_id")
        if "title" not in metadata:
            errors.append("Missing metadata.title")
        if "generated_at" not in metadata:
            errors.append("Missing metadata.generated_at")

    # Validate findings structure
    if "findings" in report_data:
        findings = report_data["findings"]
        if "total" not in findings:
            errors.append("Missing findings.total")
        if "items" not in findings:
            errors.append("Missing findings.items")
        elif not isinstance(findings["items"], list):
            errors.append("findings.items must be an array")
        else:
            for i, finding in enumerate(findings["items"]):
                if "id" not in finding:
                    errors.append(f"Finding {i}: missing id")
                if "severity" not in finding:
                    errors.append(f"Finding {i}: missing severity")
                elif finding["severity"] not in ["critical", "high", "medium", "low", "info"]:
                    errors.append(f"Finding {i}: invalid severity '{finding['severity']}'")

    if errors:
        return False, errors

    return True, None


def get_schema_json() -> str:
    """Return the full report schema as JSON string"""
    return json.dumps(REPORT_SCHEMA, indent=2)
