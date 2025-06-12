from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import DriftIssue, DriftReport, Severity


class ReportRenderer:
    def __init__(self, *, output_format: str = "terminal"):
        self.output_format = output_format

    def render(self, report: DriftReport) -> str:
        if self.output_format == "json":
            return self._render_json(report)
        if self.output_format == "html":
            return self._render_html(report)
        return self._render_terminal(report)

    def save(self, report: DriftReport, directory: Path) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        filename = directory / f"drift_report_{timestamp}.{self._extension()}"
        filename.write_text(self.render(report), encoding="utf-8")
        return filename

    def _extension(self) -> str:
        return {
            "json": "json",
            "html": "html",
        }.get(self.output_format, "txt")

    def _render_terminal(self, report: DriftReport) -> str:
        lines = [f"Documentation Drift Report — {report.summary()}"]
        if not report.issues:
            lines.append("No drift detected. Documentation looks aligned.")
            return "\n".join(lines)

        grouped = _group_by_severity(report.issues)
        for severity in (Severity.CRITICAL, Severity.MEDIUM, Severity.LOW):
            issues = grouped.get(severity, [])
            if not issues:
                continue
            lines.append("")
            lines.append(f"{severity.value.upper()} ({len(issues)})")
            for issue in issues:
                lines.append(f"- {issue.file_path}: {issue.summary}")
                lines.append(f"  Suggestion: {issue.suggestion}")
                if issue.documentation_snippet:
                    lines.append("  Doc context:")
                    for doc_line in issue.documentation_snippet.splitlines():
                        lines.append(f"    {doc_line}")
        return "\n".join(lines)

    def _render_json(self, report: DriftReport) -> str:
        payload = {
            "summary": report.summary(),
            "issues": [asdict(issue) for issue in report.issues],
        }
        return json.dumps(payload, indent=2)

    def _render_html(self, report: DriftReport) -> str:
        heading = f"<h1>Documentation Drift Report</h1><p>{report.summary()}</p>"
        if not report.issues:
            return heading + "<p>No drift detected.</p>"

        sections = []
        for issue in report.issues:
            sections.append(
                "<section>"
                f"<h2>{issue.severity.value.title()}: {issue.summary}</h2>"
                f"<p><strong>File:</strong> {issue.file_path}</p>"
                f"<p><strong>Suggestion:</strong> {issue.suggestion}</p>"
                f"<pre><code>{_escape_html(issue.code_snippet)}</code></pre>"
                "</section>"
            )
        return heading + "\n".join(sections)


def _group_by_severity(issues: list[DriftIssue]) -> dict[Severity, list[DriftIssue]]:
    grouped: dict[Severity, list[DriftIssue]] = {}
    for issue in issues:
        grouped.setdefault(issue.severity, []).append(issue)
    return grouped


def _escape_html(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )

