"""Render a Report as a text table or as the JSON document."""

from __future__ import annotations

import json
from typing import Any

from . import __version__
from .checks import FAIL, WARN, Report

STATUS_LABEL = {"pass": "PASS", "fail": "FAIL", "warn": "WARN", "skip": "skip"}


def render_table(report: Report, verbose: bool = False) -> str:
    lines = [f"mcp-auth-doctor {__version__}  spec {report.spec}  {report.url}", ""]
    width = max(len(c.id) for c in report.checks) if report.checks else 10
    for check in report.checks:
        label = STATUS_LABEL.get(check.status, check.status)
        lines.append(f"  {check.id.ljust(width)}  {label:<4}  {check.reason}")
        if verbose or check.status in (FAIL, WARN):
            for line in _evidence_lines(check.evidence):
                lines.append(f"  {' ' * width}        {line}")
    counts = report.counts()
    lines.append("")
    lines.append(
        f"{counts['pass']} pass, {counts['fail']} fail, {counts['warn']} warn, "
        f"{counts['skip']} skip. Verdict: {report.verdict.upper()} (exit {report.exit_code})"
    )
    return "\n".join(lines)


def _evidence_lines(evidence: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for key, value in evidence.items():
        if key == "attempts" and isinstance(value, list):
            for attempt in value:
                status = attempt.get("status", attempt.get("error", "?"))
                extra = (
                    f" {attempt['content_type']}"
                    if attempt.get("content_type") and attempt.get("status") == 200
                    else ""
                )
                lines.append(f"tried {attempt.get('url')} -> {status}{extra}")
            continue
        if value is None or value is False:
            continue
        if isinstance(value, (dict, list)):
            value = json.dumps(value, separators=(",", ":"))
        lines.append(f"{key}: {value}")
    return lines


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False)


__all__ = ["WARN", "render_json", "render_table"]
