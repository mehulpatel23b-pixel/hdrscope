"""Header evaluation rules and grading.

Pure functions over a plain ``{header-name: list-of-values}`` mapping so the
whole rule engine is unit-testable without touching the network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# data model
# --------------------------------------------------------------------------

GOOD = "good"      # header present & correctly configured
WARN = "warn"      # header present but weak / risky configuration
MISSING = "missing"  # header absent
INFO = "info"      # advisory, never scored

GRADED = (GOOD, WARN, MISSING)
GRADE_ORDER = ["A+", "A", "B", "C", "D", "F"]


@dataclass
class Check:
    name: str            # human-friendly check name
    header: str          # canonical header evaluated
    status: str          # GOOD | WARN | MISSING | INFO
    weight: int          # points this check is worth (0 for INFO)
    earned: int          # points actually earned
    detail: str          # what we observed
    advice: str          # concrete fix instruction


@dataclass
class AuditResult:
    url: str
    score: int = 0                 # 0-100
    grade: str = "F"
    checks: list = field(default_factory=list)
    advisories: list = field(default_factory=list)  # INFO Checks
    http_status: int = 0
    final_url: str = ""

    @property
    def satisfied(self) -> int:
        return sum(1 for c in self.checks if c.status == GOOD)

    @property
    def total_checks(self) -> int:
        return len(self.checks)


def grade_from_score(score: int) -> str:
    """Map a 0-100 score to a letter grade (securityheaders.com style)."""
    if score >= 97:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _first(headers: dict, name: str) -> str | None:
    """First (case-insensitive) value for a header name, or None."""
    for key, values in headers.items():
        if key.lower() == name.lower() and values:
            return values[0]
    return None


def _all(headers: dict, name: str) -> list[str]:
    for key, values in headers.items():
        if key.lower() == name.lower():
            return list(values)
    return []


_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
_STRICT_REFERRER = {
    "no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin",
}
_UNSAFE_CSP_TOKENS = ("unsafe-inline", "unsafe-eval", "http:", "*")
_SCRIPT_CTX_RE = re.compile(
    r"(script-src|default-src)([^;]*)", re.IGNORECASE)


def _csp_script_ctx_risky(csp: str) -> list[str]:
    """Return unsafe tokens found inside script/default-src directives."""
    findings = []
    for match in _SCRIPT_CTX_RE.finditer(csp):
        directive, blob = match.group(1), match.group(2)
        for token in _UNSAFE_CSP_TOKENS:
            if token == "*":
                # bare wildcard source (not part of a longer word)
                if re.search(r"(^|[\s;])\*(?=[\s;]|$)", blob):
                    findings.append(f"wildcard '*' in {directive}")
            elif token in blob.lower():
                findings.append(f"'{token}' in {directive}")
    # script-src falling back to unsafe default-src
    if "script-src" not in csp.lower() and "default-src" in csp.lower():
        findings.extend(_csp_script_ctx_risky(csp.replace("default-src", "script-src"))[:1])
    return findings


def _max_age_seconds(hsts: str) -> int | None:
    m = _MAX_AGE_RE.search(hsts)
    return int(m.group(1)) if m else None


# --------------------------------------------------------------------------
# individual checks — each returns a Check
# --------------------------------------------------------------------------

def _check_hsts(headers: dict) -> Check:
    val = _first(headers, "Strict-Transport-Security")
    if val is None:
        return Check("HSTS", "Strict-Transport-Security", MISSING, 15, 0,
                     "absent",
                     "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload")
    age = _max_age_seconds(val)
    if age is None or age < 15552000:  # < 180 days
        return Check("HSTS", "Strict-Transport-Security", WARN, 15, 8,
                     f"max-age={age if age is not None else '?'} (too short)",
                     "Raise max-age to at least 15552000 (ideally 31536000) seconds")
    notes = []
    if "includesubdomains" not in val.lower():
        notes.append("add includeSubDomains")
    if "preload" not in val.lower():
        notes.append("consider preload")
    return Check("HSTS", "Strict-Transport-Security", GOOD, 15, 15,
                 f"max-age={age}" + ("; includeSubDomains" if "includesubdomains" in val.lower() else ""),
                 "; ".join(notes) if notes else "Golden.")


def _check_csp(headers: dict) -> Check:
    val = _first(headers, "Content-Security-Policy")
    if val is None:
        return Check("Content-Security-Policy", "Content-Security-Policy",
                     MISSING, 20, 0, "absent",
                     "Add a CSP, e.g.: default-src 'self'; script-src 'self'; "
                     "object-src 'none'; frame-ancestors 'none'; base-uri 'self'")
    if "default-src" not in val.lower() and "script-src" not in val.lower():
        return Check("Content-Security-Policy", "Content-Security-Policy",
                     WARN, 20, 10, "present but no default-src/script-src directive",
                     "Include default-src 'self' as a fallback")
    risky = _csp_script_ctx_risky(val)
    if risky:
        return Check("Content-Security-Policy", "Content-Security-Policy",
                     WARN, 20, 10,
                     "; ".join(sorted(set(risky))),
                     "Remove unsafe-inline/unsafe-eval/wildcard from script contexts; "
                     "use nonces or hashes instead")
    return Check("Content-Security-Policy", "Content-Security-Policy", GOOD,
                 20, 20, "no unsafe script sources detected", "Golden.")


def _check_nosniff(headers: dict) -> Check:
    val = _first(headers, "X-Content-Type-Options")
    if val is None:
        return Check("X-Content-Type-Options", "X-Content-Type-Options",
                     MISSING, 10, 0, "absent",
                     "Add: X-Content-Type-Options: nosniff")
    if val.strip().lower() == "nosniff":
        return Check("X-Content-Type-Options", "X-Content-Type-Options", GOOD,
                     10, 10, "nosniff", "Golden.")
    return Check("X-Content-Type-Options", "X-Content-Type-Options", WARN,
                 10, 5, f"unexpected value '{val.strip()}'",
                 "Use exactly: X-Content-Type-Options: nosniff")


def _check_framing(headers: dict) -> Check:
    xfo = _first(headers, "X-Frame-Options")
    csp = _first(headers, "Content-Security-Policy") or ""
    fa_present = "frame-ancestors" in csp.lower()
    if xfo and xfo.strip().upper() in ("DENY", "SAMEORIGIN"):
        extra = " (CSP frame-ancestors also set)" if fa_present else \
                " — consider adding frame-ancestors to your CSP too"
        return Check("Clickjacking protection", "X-Frame-Options", GOOD, 10,
                     10, f"{xfo.strip().upper()}{extra}",
                     "Migrating to CSP frame-ancestors is the modern path.")
    if fa_present:
        return Check("Clickjacking protection", "Content-Security-Policy", GOOD,
                     10, 10, "CSP frame-ancestors set", "Golden.")
    if xfo:
        return Check("Clickjacking protection", "X-Frame-Options", WARN, 10,
                     5, f"non-standard value '{xfo.strip()}'",
                     "Use DENY or SAMEORIGIN, or CSP frame-ancestors 'none'.")
    return Check("Clickjacking protection", "X-Frame-Options", MISSING, 10, 0,
                 "neither X-Frame-Options nor CSP frame-ancestors present",
                 "Add CSP frame-ancestors 'none' (or X-Frame-Options: DENY).")


def _check_referrer(headers: dict) -> Check:
    val = _first(headers, "Referrer-Policy")
    if val is None:
        return Check("Referrer-Policy", "Referrer-Policy", MISSING, 10, 0,
                     "absent",
                     "Add: Referrer-Policy: strict-origin-when-cross-origin")
    tokens = [t.strip().lower() for t in val.split(",") if t.strip()]
    if not tokens:
        return Check("Referrer-Policy", "Referrer-Policy", WARN, 10, 3,
                     "empty policy", "Use strict-origin-when-cross-origin or stricter.")
    # Browsers apply the last valid policy in the list.
    recognized = [t for t in tokens if t in _STRICT_REFERRER
                  or t in ("no-referrer-when-downgrade", "origin", "origin-when-cross-origin")]
    effective = recognized[-1] if recognized else tokens[-1]
    if effective in _STRICT_REFERRER:
        return Check("Referrer-Policy", "Referrer-Policy", GOOD, 10, 10,
                     val.strip(), "Golden.")
    if effective in ("no-referrer-when-downgrade", "origin", "origin-when-cross-origin"):
        return Check("Referrer-Policy", "Referrer-Policy", WARN, 10, 6, val.strip(),
                     "Use strict-origin-when-cross-origin or stricter")
    return Check("Referrer-Policy", "Referrer-Policy", WARN, 10, 3,
                 f"unknown value '{val.strip()}'",
                 "Use one of: no-referrer, same-origin, strict-origin, strict-origin-when-cross-origin")


def _check_permissions(headers: dict) -> Check:
    val = _first(headers, "Permissions-Policy")
    if val is None:
        return Check("Permissions-Policy", "Permissions-Policy", MISSING, 5, 0,
                     "absent",
                     "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()")
    return Check("Permissions-Policy", "Permissions-Policy", GOOD, 5, 5,
                 val.strip()[:60], "Deny what you don't use.")


def _check_coop(headers: dict) -> Check:
    val = _first(headers, "Cross-Origin-Opener-Policy")
    if val is None:
        return Check("Cross-Origin-Opener-Policy", "Cross-Origin-Opener-Policy",
                     MISSING, 5, 0, "absent",
                     "Add: Cross-Origin-Opener-Policy: same-origin")
    v = val.strip().lower()
    ok = v in ("same-origin", "same-origin-allow-popups", "noopener")
    return Check("Cross-Origin-Opener-Policy", "Cross-Origin-Opener-Policy",
                 GOOD if ok else WARN, 5, 5 if ok else 3, v.strip(),
                 "same-origin gives the strongest isolation.")


def _check_corp(headers: dict) -> Check:
    val = _first(headers, "Cross-Origin-Resource-Policy")
    if val is None:
        return Check("Cross-Origin-Resource-Policy",
                     "Cross-Origin-Resource-Policy", MISSING, 5, 0, "absent",
                     "Add: Cross-Origin-Resource-Policy: same-origin")
    v = val.strip().lower()
    ok = v in ("same-origin", "same-site", "cross-origin")
    return Check("Cross-Origin-Resource-Policy",
                 "Cross-Origin-Resource-Policy",
                 GOOD if ok else WARN, 5, 5 if ok else 3, v.strip(), "")


def _check_cookies(headers: dict) -> Check:
    cookies = _all(headers, "Set-Cookie")
    if not cookies:
        return Check("Cookie flags", "Set-Cookie", INFO, 0, 0,
                     "no cookies on this response", "Nothing to flag.")
    problems, notes, seen = [], [], 0
    for cookie in cookies:
        seen += 1
        name = cookie.split("=", 1)[0]
        low = cookie.lower()
        if "httponly" not in low:
            problems.append(f"{name}: missing HttpOnly")
        if "secure" not in low:
            problems.append(f"{name}: missing Secure")
        m = re.search(r"samesite\s*=\s*(\w+)", cookie, re.IGNORECASE)
        if not m:
            problems.append(f"{name}: missing SameSite")
        elif m.group(1).lower() == "none" and "secure" not in low:
            problems.append(f"{name}: SameSite=None without Secure")
        elif m.group(1).lower() in ("lax", "strict", "none"):
            notes.append(f"{name}: SameSite={m.group(1)}")
    if problems:
        return Check("Cookie flags", "Set-Cookie", WARN, 10, 4,
                     f"{seen} cookie(s); " + "; ".join(problems[:4]),
                     "Set HttpOnly, Secure and SameSite=Lax (or Strict) on every cookie")
    return Check("Cookie flags", "Set-Cookie", GOOD, 10, 10,
                 f"{seen} cookie(s), all flagged correctly",
                 "; ".join(notes[:3]))


GRADED_CHECKS = (
    _check_hsts, _check_csp, _check_nosniff, _check_framing, _check_referrer,
    _check_permissions, _check_coop, _check_corp, _check_cookies,
)


def _advisory(name: str, header: str, detail: str, advice: str) -> Check:
    return Check(name, header, INFO, 0, 0, detail, advice)


def _advisories(headers: dict, http_status: int) -> list[Check]:
    out = []
    server = _first(headers, "Server")
    if server and re.search(r"\d", server):
        out.append(_advisory("Version disclosure", "Server",
                             f"'{server.strip()}' exposes version info",
                             "Strip version numbers from the Server header."))
    xp = _first(headers, "X-Powered-By")
    if xp:
        out.append(_advisory("Tech disclosure", "X-Powered-By",
                             f"'{xp.strip()}' reveals the stack",
                             "Disable X-Powered-By."))
    if _first(headers, "X-XSS-Protection"):
        out.append(_advisory("Legacy header", "X-XSS-Protection",
                             "ancient header, modern browsers ignore it",
                             "Rely on CSP instead; header can be removed."))
    cc = _first(headers, "Cache-Control")
    if http_status == 200 and (cc is None or "no-store" not in cc.lower()):
        out.append(_advisory("Caching", "Cache-Control",
                             "no 'no-store' directive seen",
                             "If the response holds private data, add Cache-Control: no-store."))
    return out


# --------------------------------------------------------------------------
# engine
# --------------------------------------------------------------------------

def evaluate_headers(headers: dict, http_status: int = 200, url: str = "") -> AuditResult:
    """Evaluate a header mapping and return a graded AuditResult.

    ``headers`` maps lowercase-able names to a list of values, e.g.::

        {"Content-Security-Policy": ["default-src 'self'"], "Set-Cookie": [...]}
    """
    result = AuditResult(url=url)
    result.http_status = http_status
    total = earned = 0
    for check_fn in GRADED_CHECKS:
        check = check_fn(headers)
        result.checks.append(check)
        total += check.weight
        earned += check.earned
    result.score = round(earned / total * 100) if total else 0
    result.grade = grade_from_score(result.score)
    result.advisories = _advisories(headers, http_status)
    return result
