"""Command-line interface for hdrscope."""

from __future__ import annotations

import argparse
import json
import sys

from .audit import AuditResult, GRADE_ORDER, GOOD, INFO, MISSING, WARN
from .fetch import FetchError, audit_url
from . import __version__

ICON = {GOOD: "✓", WARN: "⚠", MISSING: "✗", INFO: "ℹ"}
LABEL_PAD = 40

STATUS_TO_ARRAY_INDEX: dict[str, int] = {GOOD: 0, WARN: 1, MISSING: 2}


def _line(check) -> str:
    icon = ICON[check.status]
    name = check.name.ljust(LABEL_PAD - 4)[:LABEL_PAD - 4]
    pts = f"{check.earned:>2}/{check.weight:<2}" if check.weight else "   "
    return f"  {icon} {name} {pts} {check.detail}"


def text_report(result: AuditResult) -> str:
    lines = []
    lines.append("═" * 62)
    lines.append(f" hdrscope — security header audit")
    lines.append(f" target : {result.url}")
    if result.final_url and result.final_url != result.url:
        lines.append(f" landed : {result.final_url}")
    lines.append(f" status : HTTP {result.http_status}")
    lines.append("═" * 62)
    lines.append(f" SCORE {result.score}/100   GRADE [ {result.grade} ]"
                 f"   {result.satisfied}/{result.total_checks} checks pass")
    lines.append("─" * 62)
    lines.append(" HEADER CHECKS")
    for check in result.checks:
        lines.append(_line(check))
        if check.advice and check.advice not in ("Golden.", "") \
                and check.status != GOOD:
            lines.append(f"      → {check.advice}")
    if result.advisories:
        lines.append("─" * 62)
        lines.append(" ADVISORIES (not scored)")
        for adv in result.advisories:
            lines.append(_line(adv))
            if adv.advice:
                lines.append(f"      → {adv.advice}")
    lines.append("─" * 62)
    bad = [c for c in result.checks if c.status in (MISSING, WARN)]
    if bad:
        lines.append(" Fix these, then re-run hdrscope to re-grade:")
        for c in bad:
            lines.append(f"   • {c.header}: {c.advice}")
    else:
        lines.append(" Nothing to fix. Ship it. ⚡")
    lines.append("═" * 62)
    return "\n".join(lines)


def json_report(result: AuditResult) -> dict:
    return {
        "url": result.url,
        "final_url": result.final_url,
        "http_status": result.http_status,
        "score": result.score,
        "grade": result.grade,
        "checks": [
            {"name": c.name, "header": c.header, "status": c.status,
             "weight": c.weight, "earned": c.earned,
             "detail": c.detail, "advice": c.advice}
            for c in result.checks
        ],
        "advisories": [
            {"name": c.name, "header": c.header, "detail": c.detail,
             "advice": c.advice} for c in result.advisories
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hdrscope",
        description="Audit HTTP security response headers and grade them (A+ … F). "
                    "Only run hdrscope against systems you own or are authorized to test.",
    )
    parser.add_argument("urls", nargs="+", help="one or more URLs to audit")
    parser.add_argument("--json", action="store_true",
                        help="output machine-readable JSON instead of text")
    parser.add_argument("--timeout", type=int, default=15,
                        help="per-request timeout in seconds (default: 15)")
    parser.add_argument("--min-grade", default="F", metavar="GRADE",
                        choices=GRADE_ORDER,
                        help="exit with status 1 if any target grades below this "
                             "(default: F = always exit 0 on success)")
    parser.add_argument("--version", action="version",
                        version=f"hdrscope {__version__}")
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    results, errors = [], []
    for url in args.urls:
        try:
            results.append(audit_url(url, timeout=args.timeout))
        except FetchError as e:
            errors.append(str(e))

    if args.json:
        payload = {"results": [json_report(r) for r in results],
                   "errors": errors,
                   "min_grade": args.min_grade}
        print(json.dumps(payload, indent=2))
    else:
        for r in results:
            print(text_report(r))
        for err in errors:
            print(f"  ✗ {err}", file=sys.stderr)

    threshold = GRADE_ORDER.index(args.min_grade)
    below = [r for r in results
             if GRADE_ORDER.index(r.grade) > threshold]

    if errors:
        return 2
    if below:
        return 1
    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
