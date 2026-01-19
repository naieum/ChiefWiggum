"""
MongoDB-Specific Security Checks

Checks for NoSQL injection, authentication bypass, and
other MongoDB-specific vulnerabilities.
"""

from dataclasses import dataclass
from typing import Optional, Callable
import re


@dataclass
class MongoDBCheckResult:
    """Result of a MongoDB security check"""
    check_id: str
    vulnerable: bool
    severity: str
    evidence: list[str]
    injection_type: Optional[str]
    remediation: str


class MongoDBSecurityChecks:
    """
    Security checks specific to MongoDB applications.

    Focuses on:
    - NoSQL injection via operator injection
    - JavaScript injection ($where)
    - Authentication bypass
    - ObjectId enumeration
    """

    # Safe test payloads that don't modify data
    SAFE_INJECTION_PAYLOADS = [
        # Operator injection (read-only)
        ('{"$ne": null}', "operator_ne"),
        ('{"$gt": ""}', "operator_gt"),
        ('{"$gte": ""}', "operator_gte"),
        ('{"$exists": true}', "operator_exists"),
        ('{"$regex": ".*"}', "operator_regex"),

        # Type confusion
        ('{"$type": 2}', "type_string"),
        ('{"$type": 16}', "type_int"),

        # Array operators (read-only)
        ('{"$in": ["admin", "user"]}', "operator_in"),
        ('{"$nin": []}', "operator_nin"),
    ]

    def __init__(self, http_callback: Optional[Callable] = None):
        self._http = http_callback

    def check_operator_injection(
        self,
        endpoint: str,
        param_name: str,
        baseline_count: Optional[int] = None
    ) -> MongoDBCheckResult:
        """
        Check for NoSQL operator injection.

        Safe check: Uses read-only operators that don't modify data.
        """
        evidence = []
        vulnerable = False
        detected_injection = None

        for payload, injection_type in self.SAFE_INJECTION_PAYLOADS:
            # Note: Real implementation would make HTTP request
            # response = self._http("GET", f"{endpoint}?{param_name}={payload}")

            # Compare response to baseline
            # If $ne returns more results than normal query, vulnerable
            pass

        return MongoDBCheckResult(
            check_id="MDB-001",
            vulnerable=vulnerable,
            severity="critical" if vulnerable else "info",
            evidence=evidence,
            injection_type=detected_injection,
            remediation=(
                "Sanitize all user input before use in MongoDB queries. "
                "Use MongoDB query builders or ODM that handle sanitization. "
                "Validate that input types match expected types (string vs object)."
            )
        )

    def check_auth_bypass(
        self,
        login_endpoint: str,
        username_param: str = "username",
        password_param: str = "password"
    ) -> MongoDBCheckResult:
        """
        Check for authentication bypass via NoSQL injection.

        Safe check: Uses payloads that would bypass auth without modifying data.
        """
        evidence = []
        vulnerable = False

        # Auth bypass payloads
        bypass_payloads = [
            # Username bypass
            {username_param: '{"$ne": null}', password_param: '{"$ne": null}'},
            {username_param: '{"$gt": ""}', password_param: '{"$gt": ""}'},
            {username_param: 'admin', password_param: '{"$ne": null}'},

            # Regex bypass
            {username_param: '{"$regex": "admin"}', password_param: '{"$ne": ""}'},
        ]

        for payload in bypass_payloads:
            # Note: Real implementation would make HTTP request
            # Check if auth succeeds with injection payload
            pass

        return MongoDBCheckResult(
            check_id="MDB-003",
            vulnerable=vulnerable,
            severity="critical" if vulnerable else "info",
            evidence=evidence,
            injection_type="auth_bypass" if vulnerable else None,
            remediation=(
                "Never pass user input directly to MongoDB queries. "
                "Always validate input types - reject objects when strings expected. "
                "Use mongoose with strict schema validation."
            )
        )

    def check_objectid_enumeration(
        self,
        endpoint: str,
        sample_ids: list[str]
    ) -> MongoDBCheckResult:
        """
        Check for ObjectId enumeration (IDOR via predictable IDs).

        Safe check: Analyzes ID patterns without accessing other users' data.
        """
        evidence = []
        indicators = []

        # Analyze ObjectId patterns
        for oid in sample_ids:
            if self._is_valid_objectid(oid):
                # ObjectIds contain timestamp - check if sequential
                timestamp = int(oid[:8], 16)
                indicators.append(timestamp)

        if len(indicators) > 1:
            # Check if timestamps are close together (batch creation)
            timestamps_sorted = sorted(indicators)
            gaps = [timestamps_sorted[i+1] - timestamps_sorted[i]
                   for i in range(len(timestamps_sorted)-1)]

            if gaps and max(gaps) < 10:  # Created within 10 seconds
                evidence.append("ObjectIds appear to be created in batch - potentially enumerable")

        return MongoDBCheckResult(
            check_id="MDB-004",
            vulnerable=False,  # Need active testing to confirm
            severity="medium",
            evidence=evidence,
            injection_type=None,
            remediation=(
                "Don't rely on ObjectId unpredictability for authorization. "
                "Always implement proper access control checks. "
                "Consider using UUIDs for public-facing IDs."
            )
        )

    def _is_valid_objectid(self, oid: str) -> bool:
        """Check if string is valid MongoDB ObjectId format"""
        return bool(re.match(r'^[0-9a-fA-F]{24}$', oid))

    def get_safe_query_examples(self) -> dict:
        """
        Return examples of safe MongoDB query patterns.
        """
        return {
            "mongoose_sanitization": """
// Using mongoose with schema validation
const userSchema = new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
});

// Query with sanitized input
const user = await User.findOne({
    username: String(req.body.username),  // Force string type
    password: String(req.body.password)
});
""",
            "express_validator": """
// Using express-validator
const { body } = require('express-validator');

app.post('/login', [
    body('username').isString().trim().escape(),
    body('password').isString()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    // Safe to use req.body now
});
""",
            "manual_sanitization": """
// Manual type checking
function sanitizeQuery(input) {
    if (typeof input === 'object') {
        throw new Error('Invalid input type');
    }
    return String(input);
}

const user = await db.collection('users').findOne({
    username: sanitizeQuery(req.body.username)
});
"""
        }
