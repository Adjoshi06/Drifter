from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from .config import Settings
from .doc_discovery import DocumentationFinder
from .git_analysis import GitAnalyzer
from .llm import LLMClient
from .models import (
    ChangeType,
    DriftCandidate,
    DriftIssue,
    DriftReport,
    DriftType,
    DocumentationReference,
    RepositoryChanges,
    Severity,
)

logger = logging.getLogger(__name__)


@dataclass
class DriftDetectorConfig:
    repo_path: Path
    severity_threshold: Severity = Severity.LOW
    ignore_private_functions: bool = True
    check_examples: bool = True
    check_inline_comments: bool = True


class DriftDetector:
    def __init__(
        self,
        analyzer: GitAnalyzer,
        documentation_finder: DocumentationFinder,
        llm_client: LLMClient,
        config: DriftDetectorConfig,
    ):
        self.analyzer = analyzer
        self.documentation_finder = documentation_finder
        self.llm = llm_client
        self.config = config

    @classmethod
    def from_settings(cls, settings: Settings, llm_client: LLMClient) -> "DriftDetector":
        severity = _parse_severity(settings.analysis.severity_threshold)
        config = DriftDetectorConfig(
            repo_path=settings.repo_path,
            severity_threshold=severity,
            ignore_private_functions=settings.analysis.auto_ignore_private_functions,
            check_examples=settings.analysis.check_examples,
            check_inline_comments=settings.analysis.check_inline_comments,
        )
        analyzer = GitAnalyzer(settings.repo_path)
        documentation_finder = DocumentationFinder(settings.repo_path)
        documentation_finder.build_index()
        return cls(analyzer, documentation_finder, llm_client, config)

    def run(
        self,
        *,
        from_ref: Optional[str] = None,
        to_ref: Optional[str] = None,
        since: Optional[str] = None,
        branch: Optional[str] = None,
    ) -> DriftReport:
        repo_changes = self.analyzer.collect_changes(
            from_ref=from_ref,
            to_ref=to_ref,
            since=since,
            branch=branch,
        )
        candidates = list(self._generate_candidates(repo_changes))
        issues: List[DriftIssue] = []

        for candidate in candidates:
            issue = self.llm.generate_issue(candidate)
            if _severity_meets_threshold(issue.severity, self.config.severity_threshold):
                issues.append(issue)

        return DriftReport(issues=issues)

    def _generate_candidates(
        self, repo_changes: RepositoryChanges
    ) -> Iterable[DriftCandidate]:
        for change in repo_changes.changes:
            docs = self._fetch_documentation(change.symbol, repo_changes)

            if change.symbol and self._should_ignore_symbol(change.symbol):
                continue

            if (
                change.change_type == ChangeType.ADDED
                and change.language == "python"
                and change.new_signature
                and not change.new_signature.has_docstring
            ):
                description = (
                    f"Function {change.symbol} was added without a docstring. "
                    "Public functions should describe parameters and return values."
                )
                yield DriftCandidate(
                    change=change,
                    drift_type=DriftType.MISSING_DOCSTRING,
                    description=description,
                    documentation=docs,
                )
                continue

            if (
                change.change_type == ChangeType.MODIFIED
                and change.language == "python"
                and change.old_signature
                and change.new_signature
                and change.old_signature.signature != change.new_signature.signature
            ):
                if not docs or all(ref.changed is False for ref in docs):
                    description = (
                        f"The signature for {change.symbol} changed from "
                        f"{change.old_signature.signature} to "
                        f"{change.new_signature.signature}, but associated "
                        "documentation does not appear to reflect this update."
                    )
                    yield DriftCandidate(
                        change=change,
                        drift_type=DriftType.OUTDATED_SIGNATURE,
                        description=description,
                        documentation=docs,
                    )
                continue

            if (
                change.change_type == ChangeType.REMOVED
                and change.language == "python"
                and docs
                and all(ref.changed is False for ref in docs)
            ):
                description = (
                    f"Function {change.symbol} was removed, yet references remain in "
                    "documentation that did not change in this diff."
                )
                yield DriftCandidate(
                    change=change,
                    drift_type=DriftType.REMOVED_FEATURE,
                    description=description,
                    documentation=docs,
                )
                continue

            if change.language != "python" and docs and change.change_type in {
                ChangeType.ADDED,
                ChangeType.MODIFIED,
            }:
                unchanged_docs = [ref for ref in docs if not ref.changed]
                if unchanged_docs:
                    description = (
                        f"{change.file_path} changed but related documentation was not "
                        "updated."
                    )
                    yield DriftCandidate(
                        change=change,
                        drift_type=DriftType.GENERAL_DRIFT,
                        description=description,
                        documentation=docs,
                    )

    def _fetch_documentation(
        self, symbol: Optional[str], repo_changes: RepositoryChanges
    ) -> List[DocumentationReference]:
        if not symbol:
            return []
        return self.documentation_finder.references_for_symbol(
            symbol, changed_docs=list(repo_changes.documentation_files_changed)
        )

    def _should_ignore_symbol(self, symbol: str) -> bool:
        if not self.config.ignore_private_functions:
            return False
        if symbol.startswith("_") and not symbol.startswith("__"):
            return True
        return False


def _parse_severity(value: str) -> Severity:
    normalized = value.strip().lower()
    for severity in Severity:
        if severity.value == normalized:
            return severity
    return Severity.LOW


def _severity_meets_threshold(value: Severity, threshold: Severity) -> bool:
    order = {
        Severity.CRITICAL: 3,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
    }
    return order[value] >= order[threshold]

