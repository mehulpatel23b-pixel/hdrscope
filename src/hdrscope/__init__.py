"""hdrscope — zero-dependency HTTP security-header auditor.

Fetch a page, evaluate its security response headers and cookie flags,
produce a securityheaders.com-style grade with concrete fix advice.
"""

__version__ = "1.0.0"
__all__ = ["audit_url", "evaluate_headers", "grade_from_score", "GRADE_ORDER"]
